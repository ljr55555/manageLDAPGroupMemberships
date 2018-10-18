# manageLDAPGroupMemberships
There is an effort under way to have our in-house developed applications return "friendlier" error messages
when individuals access functions for which they are unauthorized. To test each possible scenario, our
development team needed to change their group memberships quite frequently. We did not want to permit them
to modify the entire group, but asking them to wait for someone to get around to updating their membership
was unreasonable. I created this quick page to allow a developer to add/remove themselves from a list
of in-scope LDAP groups without risking accidental deletion of other members. 
