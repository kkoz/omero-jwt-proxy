import omero
import omero.clients
from omero.rtypes import rint, rlong, rstring, rtime, rbool
from omero.model import ExperimenterGroupI, ExperimenterI, \
    PermissionsI 
from omero import ApiUsageException, RemovedSessionException

import logging


log = logging.getLogger('omero_connection_manager')
log.setLevel('INFO')


#### OMERO Interactions ####
class OmeroConnectionManager:

    def __init__(self):
        return

    def init_session(self, group=None):
        if group is None:
            group = '-1'
        self.ice_session.detachOnDestroy()
        self.client.getImplicitContext().put(omero.constants.GROUP, group)
        log.debug('Set group context to: %r' % group)
        self.event_context = \
            self.ice_session.getAdminService().getEventContext()
        self.session_key = self.event_context.sessionUuid
        self.username = self.event_context.userName
        self.admin_service = self.ice_session.getAdminService()
        self.session_service = self.ice_session.getSessionService()

    def create_session(self, group=None):
        username = 'root'
        password = 'omero'
        log.info('Attempting to create sessions for %s' % username)
        server = 'localhost'
        port = 4064
        self.client = omero.client(server, port)
        self.ice_session = self.client.createSession(username, password)
        self.init_session(group=group)
        self.password = password
        log.info('Successful login for %r with session %r' % (username, self.session_key))

    def close_session(self):
        self.client.closeSession()

    
    def create_or_update_user(self, firstname, lastname, username, password, group, is_admin=False):
        """
        Creates or updates an experimenter and group. If the user does not
        exist he/she will be created. The user will also be added to
        the group specified (if the group does not exist it will be
        created) and added to the admin group if specified.
        """
        # First we need to create a manuscript group and experimenter
        permissions = PermissionsI('rwrw--')
        new_group = ExperimenterGroupI()
        new_group.name = rstring(group.encode('utf_8'))
        new_group.details.permissions = permissions
        new_group.ldap = rbool(False)
        log.info(new_group.getLdap())

        new_user = ExperimenterI()
        new_user.omeName = rstring(username.encode('utf_8'))
        new_user.firstName = rstring(firstname.encode('utf_8'))
        new_user.lastName = rstring(lastname.encode('utf_8'))
        new_user.ldap = rbool(False)

        # Ensure that our password is an RType
        if password is not None:
            password = rstring(password.encode('utf_8'))

        # Before we attempt saving we must remove any group context from
        # the implicit context.  Otherwise saves will fail.
        ic = self.client.getImplicitContext()
        group_context = ic.remove(omero.constants.GROUP)
        # Save our new group and experimenter in the database, if the user
        # does not exist. If it does, make the user a member of the group
        # and make that group the user's default.
        try:
            try:
                group_id = self.admin_service.lookupGroup(group).getId()
            except ApiUsageException:
                group_id = rlong(self.admin_service.createGroup(new_group))
            if is_admin:
                admin_group_id = \
                    self.admin_service.lookupGroup("system").getId()
                unloaded_admin_group = \
                    ExperimenterGroupI(admin_group_id, False)
            try:
                # Existing user code path
                groups = list()
                if is_admin:
                    groups.append(unloaded_admin_group)
                new_user = self.admin_service.lookupExperimenter(username)
                unloaded_group = ExperimenterGroupI(group_id, False)
                groups.append(unloaded_group)
                self.admin_service.addGroups(new_user, groups)
                self.admin_service.setDefaultGroup(new_user, unloaded_group)
                if password is not None:
                    self.admin_service.changeUserPassword(username, password)
            except ApiUsageException:
                # New user code path
                self.admin_service.createUser(new_user, group)
                self.admin_service.changeUserPassword(username, password)
                new_user = self.admin_service.lookupExperimenter(username)
                if is_admin:
                    self.admin_service.addGroups(
                        new_user, [unloaded_admin_group]
                    )
        finally:
            if len(group_context) > 0:
                # Ice uses empty strings to signify null
                ic.put(omero.constants.GROUP, group_context)

    def create_session_with_timeout(self, username, group, timeout=60000):
        """
        Creates a new session for a user.
        """
        p = omero.sys.Principal()
        p.name = username
        p.group = group
        p.eventType = "User"
        session = self.session_service.createSessionWithTimeout(p, timeout)
        log.info(
            "Created session %r timeout=%d with principal: %r" %
                (session.uuid.val, timeout, p)
        )
        return session

