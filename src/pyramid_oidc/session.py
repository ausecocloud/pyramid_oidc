# A custom session factory .....
# - uses dogpile backends.
# - steal as much from redis session ....
#   - dogpile does memory, file, redis? and others
import base64
import binascii
import hashlib
import hmac
import json
import os
import time

from dogpile.cache import make_region
from dogpile.cache.api import NO_VALUE
from pyramid.interfaces import ISession
from pyramid.util import strings_differ
from zope.interface import implementer


def signed_serialize(data, secret):
    """ Serialize any pickleable structure (``data``) and sign it
    using the ``secret`` (must be a string).  Return the
    serialization, which includes the signature as its first 40 bytes.
    The ``signed_deserialize`` method will deserialize such a value.
    This function is useful for creating signed cookies.  For example:
    .. code-block:: python
       cookieval = signed_serialize({'a':1}, 'secret')
       response.set_cookie('signed_cookie', cookieval)
    """
    payload = json.dumps(data).encode('utf-8')
    sig = hmac.new(secret, payload, hashlib.sha1).hexdigest()
    return sig.encode('utf-8') + base64.b64encode(payload)


def signed_deserialize(serialized, secret, hmac=hmac):
    """ Deserialize the value returned from ``signed_serialize``.  If
    the value cannot be deserialized for any reason, a
    :exc:`ValueError` exception will be raised.
    This function is useful for deserializing a signed cookie value
    created by ``signed_serialize``.  For example:
    .. code-block:: python
       cookieval = request.cookies['signed_cookie']
       data = signed_deserialize(cookieval, 'secret')
    """
    # hmac parameterized only for unit tests
    try:
        input_sig, payload = (serialized[:40],
                              base64.b64decode(serialized[40:]))
    except (binascii.Error, TypeError) as e:
        # Badly formed data can make base64 die
        raise ValueError('Badly formed base64 data: %s' % e)

    sig = hmac.new(secret, payload, hashlib.sha1).hexdigest()

    # Avoid timing attacks (see
    # http://seb.dbzteam.org/crypto/python-oauth-timing-hmac.pdf)
    if strings_differ(sig, input_sig):
        raise ValueError('Invalid signature')

    return json.loads(payload)


def _generate_secret():
    return os.urandom(32)


def _generate_session_id():
    rand = os.urandom(20)
    return hashlib.sha256(hashlib.sha256(rand).digest()).hexdigest()


# TODO: be careful with cookie max age ...
#       e.g. user comes back after a week and sends session_id of already
#       existing session of other user?

class SessionFactory(object):

    def __init__(self, secret=None, timeout=1200, refresh=None,
                 cookie_opts={}, on_excpetion=True,
                 dogpile_opts={}):
        # secret ... cookie signature
        # timeout ... session / cookie timeout in seconds
        #

        # our session cache region .... created once per process

        self.dogpile_opts = {
            'backend': 'dogpile.cache.memory',
            'expiration_time': timeout,
        }
        self.dogpile_opts.update(dogpile_opts)

        self.region = make_region(
            name='oidc.session',
        ).configure_from_config(self.dogpile_opts, '')
        if self.dogpile_opts.pop('debug', False):
            from pyramid_debugtoolbar_dogpile import LoggingProxy
            self.region.wrap(LoggingProxy)

        if secret:
            self.secret = secret.encode('utf-8')
        else:
            self.secret = _generate_secret()
        self.timeout = timeout
        if refresh is None:
            self.refresh = timeout // 2
        else:
            self.refresh = refresh
        self.cookie_opts = {
            'name': 'session',
            # 'value'
            'max_age': self.timeout,
            'path': '/',
            'domain': None,
            'secure': False,
            'httponly': True,
            # 'samesite': None, b"Strict", b"Lax"
            # 'comment" : None
            # 'overwrite': True
        }
        self.on_exception = on_excpetion
        self.cookie_opts.update(cookie_opts)
        self.id_generator = _generate_session_id

    def _get_session_id_from_cookie(self, request):
        cookieval = request.cookies.get(self.cookie_opts['name'])
        if cookieval is not None:
            try:
                session_id = signed_deserialize(cookieval, self.secret)
                return session_id
            except ValueError:
                pass

        return None

    def _new_session_id(self):
        while 1:
            session_id = self.id_generator()
            if self.region.get(session_id) is NO_VALUE:
                break
        return session_id

    def _cookie_callback(self, request, response):
        # ... here we have to deal with, cookite timeout and refresh
        #     also if session is new, and in case we want to delete
        #     the session cookie

        if not self.on_exception:
            exception = getattr(self.request, 'exception', None)
            if exception is not None:  # dont set a cookie during exceptions
                return False

        session = request.session

        if session._deleted:
            response.delete_cookie(
                name=self.cookie_opts['name'],
                path=self.cookie_opts['path'],
                domain=self.cookie_opts['domain']
            )
            return True

        # check if we need to refresh the cookie?
        if session._dirty:
            session._save_state()

            if session.new or (time.time() - session.renewed > self.refresh):
                cookieval = signed_serialize(session.session_id, self.secret)
                response.set_cookie(
                    value=cookieval,
                    **self.cookie_opts
                )
        # self.request = None  # explicitly break cycle for gc
        return True

    def __call__(self, request):
        # create a new session object here
        session_id = self._get_session_id_from_cookie(request)
        # no session id yet ... create a new one
        if not session_id:
            session_id = self._new_session_id()
        # we have a session id
        session = DogpileSession(self.region, session_id)
        # add request callbakc to send session_id bakc to user
        request.add_response_callback(self._cookie_callback)
        # return new session
        # we really assume, that the current request object caches this session
        # and that within the same thread this method get's called only once.
        # If another thread or process creates a new session as well, we
        # may run into problems, but these should be solved at the session
        # (dogpile) level.
        return session


def manage_accessed(wrapped):
    """ Decorator which causes a session to be renewed when an accessor
    method is called."""
    def accessed(session, *arg, **kw):
        session.accessed = now = int(time.time())
        if session._reissue_time is not None:
            if now - session.renewed > session._reissue_time:
                session.changed()
        return wrapped(session, *arg, **kw)
    accessed.__doc__ = wrapped.__doc__
    return accessed


def manage_changed(wrapped):
    """ Decorator which causes a session to be set when a setter method
    is called."""
    def changed(session, *arg, **kw):
        session.accessed = int(time.time())
        session.changed()
        return wrapped(session, *arg, **kw)
    changed.__doc__ = wrapped.__doc__
    return changed


@implementer(ISession)
class DogpileSession(object):

    # manage methods:
    accessed = None
    _reissue_time = None
    renewed = None

    # TODO: this implementation may be a bit inefficient, as it refreshes
    #       all values all the time ... even just on access

    def __init__(self, region, session_id):
        # state attributes

        self.region = region
        self.session_id = session_id

        now = time.time()
        self.created = now
        self.renewed = now
        self.new = True

        self._dirty = False
        self._deleted = False
        self._flash = {}

        self._load_state()

    def _load_state(self):
        # TODO: what about NO_VALUE?
        # TODO: update self.created?
        _state = self.region.get(self.session_id)
        if _state is not NO_VALUE:
            # TODO: possible key conflict?
            self.created = _state['created']
            self.renewed = _state['renewed']
            self.new = False
            self.data = _state['data']
        else:
            self.data = {}

    def _save_state(self):
        self.region.set(
            self.session_id,
            {
                'created': self.created,
                'renewed': self.renewed,
                'data': self.data
            }
        )
        self._deleted = False
        self._dirty = False

    @manage_accessed
    def __contains__(self, k):
        """ Return ``True`` if key ``k`` exists in the dictionary."""
        return k in self.data

    @manage_changed
    def __setitem__(self, k, value):
        """ Set a key/value pair into the dictionary"""
        self.data[k] = value

    @manage_changed
    def __delitem__(self, k):
        """ Delete an item from the dictionary which is passed to the
        renderer as the renderer globals dictionary."""
        del self.data[k]

    @manage_accessed
    def __getitem__(self, k):
        """ Return the value for key ``k`` from the dictionary or raise a
        KeyError if the key doesn't exist"""
        return self.data[k]

    @manage_accessed
    def __iter__(self):
        """ Return an iterator over the keys of this dictionary """
        return iter(self.data)

    @manage_accessed
    def get(self, k, default=None):
        """ Return the value for key ``k`` from the renderer dictionary, or
        the default if no such value exists."""
        return self.data.get(k, default)

    @manage_accessed
    def items(self):
        """ Return a list of [(k,v)] pairs from the dictionary """
        return self.data.items()

    @manage_accessed
    def keys(self):
        """ Return a list of keys from the dictionary """
        return self.data.keys()

    @manage_accessed
    def values(self):
        """ Return a list of values from the dictionary """
        return self.data.values()

    @manage_changed
    def pop(self, k, default=None):
        """ Pop the key k from the dictionary and return its value.  If k
        doesn't exist, and default is provided, return the default.  If k
        doesn't exist and default is not provided, raise a KeyError."""
        return self.data.pop(k, default)

    @manage_changed
    def popitem(self):
        """ Pop the item with key k from the dictionary and return it as a
        two-tuple (k, v).  If k doesn't exist, raise a KeyError."""
        return self.data.popitem()

    @manage_changed
    def setdefault(self, k, default=None):
        """ Return the existing value for key ``k`` in the dictionary.  If no
         value with ``k`` exists in the dictionary, set the ``default``
         value into the dictionary under the k name passed.  If a value already
         existed in the dictionary, return it.  If a value did not exist in
         the dictionary, return the default"""
        return self.data.setdefault(k, default)

    @manage_changed
    def update(self, d):
        """ Update the renderer dictionary with another dictionary ``d``."""
        self.data.update(d)

    @manage_changed
    def clear(self):
        """ Clear all values from the dictionary """
        self.data.clear()

    def invalidate(self):
        """ Invalidate the session.  The action caused by
        ``invalidate`` is implementation-dependent, but it should have
        the effect of completely dissociating any data stored in the
        session with the current request.  It might set response
        values (such as one which clears a cookie), or it might not.
        An invalidated session may be used after the call to ``invalidate``
        with the effect that a new session is created to store the data. This
        enables workflows requiring an entirely new session, such as in the
        case of changing privilege levels or preventing fixation attacks.
        """

        # TODO: should be no problem to support new session here?
        self.region.delete(self.session_id)
        self._deleted = True

    def changed(self):
        """ Mark the session as changed. A user of a session should
        call this method after he or she mutates a mutable object that
        is *a value of the session* (it should not be required after
        mutating the session itself).  For example, if the user has
        stored a dictionary in the session under the key ``foo``, and
        he or she does ``session['foo'] = {}``, ``changed()`` needn't
        be called.  However, if subsequently he or she does
        ``session['foo']['a'] = 1``, ``changed()`` must be called for
        the sessioning machinery to notice the mutation of the
        internal dictionary."""

        # TODO: should we add some sort of transactional behaviour?
        #       we don't really want our session to change in mid request?
        #       would probably be good to have some sort of conflict resolution?
        self._dirty = True

    def flash(self, msg, queue='', allow_duplicate=True):
        """ Push a flash message onto the end of the flash queue represented
        by ``queue``.  An alternate flash message queue can used by passing
        an optional ``queue``, which must be a string.  If
        ``allow_duplicate`` is false, if the ``msg`` already exists in the
        queue, it will not be re-added."""
        storage = self._flash.setdefault(queue, [])
        if allow_duplicate or (msg not in storage):
            storage.append(msg)

    def pop_flash(self, queue=''):
        """ Pop a queue from the flash storage.  The queue is removed from
        flash storage after this message is called.  The queue is returned;
        it is a list of flash messages added by
        :meth:`pyramid.interfaces.ISession.flash`"""
        storage = self._flash.pop(queue, [])
        return storage

    def peek_flash(self, queue=''):
        """ Peek at a queue in the flash storage.  The queue remains in
        flash storage after this message is called.  The queue is returned;
        it is a list of flash messages added by
        :meth:`pyramid.interfaces.ISession.flash`
        """
        storage = self._flash.get(queue, [])
        return storage
