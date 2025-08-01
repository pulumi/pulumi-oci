# coding=utf-8
# *** WARNING: this file was generated by pulumi-language-python. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import builtins as _builtins
import warnings
import sys
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
if sys.version_info >= (3, 11):
    from typing import NotRequired, TypedDict, TypeAlias
else:
    from typing_extensions import NotRequired, TypedDict, TypeAlias
from .. import _utilities
from . import outputs

__all__ = [
    'GetTargetDatabasePeerTargetDatabaseResult',
    'AwaitableGetTargetDatabasePeerTargetDatabaseResult',
    'get_target_database_peer_target_database',
    'get_target_database_peer_target_database_output',
]

@pulumi.output_type
class GetTargetDatabasePeerTargetDatabaseResult:
    """
    A collection of values returned by getTargetDatabasePeerTargetDatabase.
    """
    def __init__(__self__, database_details=None, database_unique_name=None, dataguard_association_id=None, description=None, display_name=None, id=None, key=None, lifecycle_details=None, peer_target_database_id=None, role=None, state=None, target_database_id=None, time_created=None, tls_configs=None):
        if database_details and not isinstance(database_details, list):
            raise TypeError("Expected argument 'database_details' to be a list")
        pulumi.set(__self__, "database_details", database_details)
        if database_unique_name and not isinstance(database_unique_name, str):
            raise TypeError("Expected argument 'database_unique_name' to be a str")
        pulumi.set(__self__, "database_unique_name", database_unique_name)
        if dataguard_association_id and not isinstance(dataguard_association_id, str):
            raise TypeError("Expected argument 'dataguard_association_id' to be a str")
        pulumi.set(__self__, "dataguard_association_id", dataguard_association_id)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if key and not isinstance(key, int):
            raise TypeError("Expected argument 'key' to be a int")
        pulumi.set(__self__, "key", key)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if peer_target_database_id and not isinstance(peer_target_database_id, str):
            raise TypeError("Expected argument 'peer_target_database_id' to be a str")
        pulumi.set(__self__, "peer_target_database_id", peer_target_database_id)
        if role and not isinstance(role, str):
            raise TypeError("Expected argument 'role' to be a str")
        pulumi.set(__self__, "role", role)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if target_database_id and not isinstance(target_database_id, str):
            raise TypeError("Expected argument 'target_database_id' to be a str")
        pulumi.set(__self__, "target_database_id", target_database_id)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if tls_configs and not isinstance(tls_configs, list):
            raise TypeError("Expected argument 'tls_configs' to be a list")
        pulumi.set(__self__, "tls_configs", tls_configs)

    @_builtins.property
    @pulumi.getter(name="databaseDetails")
    def database_details(self) -> Sequence['outputs.GetTargetDatabasePeerTargetDatabaseDatabaseDetailResult']:
        """
        Details of the database for the registration in Data Safe.
        """
        return pulumi.get(self, "database_details")

    @_builtins.property
    @pulumi.getter(name="databaseUniqueName")
    def database_unique_name(self) -> _builtins.str:
        """
        Unique name of the database associated to the peer target database.
        """
        return pulumi.get(self, "database_unique_name")

    @_builtins.property
    @pulumi.getter(name="dataguardAssociationId")
    def dataguard_association_id(self) -> _builtins.str:
        """
        The OCID of the Data Guard Association resource in which the database associated to the peer target database is considered as peer database to the primary database.
        """
        return pulumi.get(self, "dataguard_association_id")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        The description of the peer target database in Data Safe.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        The display name of the peer target database in Data Safe.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter
    def key(self) -> _builtins.int:
        """
        The secondary key assigned for the peer target database in Data Safe.
        """
        return pulumi.get(self, "key")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Details about the current state of the peer target database in Data Safe.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="peerTargetDatabaseId")
    def peer_target_database_id(self) -> _builtins.str:
        return pulumi.get(self, "peer_target_database_id")

    @_builtins.property
    @pulumi.getter
    def role(self) -> _builtins.str:
        """
        Role of the database associated to the peer target database.
        """
        return pulumi.get(self, "role")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the peer target database in Data Safe.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="targetDatabaseId")
    def target_database_id(self) -> _builtins.str:
        return pulumi.get(self, "target_database_id")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time of the peer target database registration in Data Safe.
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="tlsConfigs")
    def tls_configs(self) -> Sequence['outputs.GetTargetDatabasePeerTargetDatabaseTlsConfigResult']:
        """
        The details required to establish a TLS enabled connection.
        """
        return pulumi.get(self, "tls_configs")


class AwaitableGetTargetDatabasePeerTargetDatabaseResult(GetTargetDatabasePeerTargetDatabaseResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetTargetDatabasePeerTargetDatabaseResult(
            database_details=self.database_details,
            database_unique_name=self.database_unique_name,
            dataguard_association_id=self.dataguard_association_id,
            description=self.description,
            display_name=self.display_name,
            id=self.id,
            key=self.key,
            lifecycle_details=self.lifecycle_details,
            peer_target_database_id=self.peer_target_database_id,
            role=self.role,
            state=self.state,
            target_database_id=self.target_database_id,
            time_created=self.time_created,
            tls_configs=self.tls_configs)


def get_target_database_peer_target_database(peer_target_database_id: Optional[_builtins.str] = None,
                                             target_database_id: Optional[_builtins.str] = None,
                                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetTargetDatabasePeerTargetDatabaseResult:
    """
    This data source provides details about a specific Target Database Peer Target Database resource in Oracle Cloud Infrastructure Data Safe service.

    Returns the details of the specified Data Safe peer target database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_target_database_peer_target_database = oci.DataSafe.get_target_database_peer_target_database(peer_target_database_id=test_target_database["id"],
        target_database_id=test_target_database["id"])
    ```


    :param _builtins.str peer_target_database_id: The unique id of the peer target database.
    :param _builtins.str target_database_id: The OCID of the Data Safe target database.
    """
    __args__ = dict()
    __args__['peerTargetDatabaseId'] = peer_target_database_id
    __args__['targetDatabaseId'] = target_database_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getTargetDatabasePeerTargetDatabase:getTargetDatabasePeerTargetDatabase', __args__, opts=opts, typ=GetTargetDatabasePeerTargetDatabaseResult).value

    return AwaitableGetTargetDatabasePeerTargetDatabaseResult(
        database_details=pulumi.get(__ret__, 'database_details'),
        database_unique_name=pulumi.get(__ret__, 'database_unique_name'),
        dataguard_association_id=pulumi.get(__ret__, 'dataguard_association_id'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        id=pulumi.get(__ret__, 'id'),
        key=pulumi.get(__ret__, 'key'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        peer_target_database_id=pulumi.get(__ret__, 'peer_target_database_id'),
        role=pulumi.get(__ret__, 'role'),
        state=pulumi.get(__ret__, 'state'),
        target_database_id=pulumi.get(__ret__, 'target_database_id'),
        time_created=pulumi.get(__ret__, 'time_created'),
        tls_configs=pulumi.get(__ret__, 'tls_configs'))
def get_target_database_peer_target_database_output(peer_target_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                    target_database_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetTargetDatabasePeerTargetDatabaseResult]:
    """
    This data source provides details about a specific Target Database Peer Target Database resource in Oracle Cloud Infrastructure Data Safe service.

    Returns the details of the specified Data Safe peer target database.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_target_database_peer_target_database = oci.DataSafe.get_target_database_peer_target_database(peer_target_database_id=test_target_database["id"],
        target_database_id=test_target_database["id"])
    ```


    :param _builtins.str peer_target_database_id: The unique id of the peer target database.
    :param _builtins.str target_database_id: The OCID of the Data Safe target database.
    """
    __args__ = dict()
    __args__['peerTargetDatabaseId'] = peer_target_database_id
    __args__['targetDatabaseId'] = target_database_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getTargetDatabasePeerTargetDatabase:getTargetDatabasePeerTargetDatabase', __args__, opts=opts, typ=GetTargetDatabasePeerTargetDatabaseResult)
    return __ret__.apply(lambda __response__: GetTargetDatabasePeerTargetDatabaseResult(
        database_details=pulumi.get(__response__, 'database_details'),
        database_unique_name=pulumi.get(__response__, 'database_unique_name'),
        dataguard_association_id=pulumi.get(__response__, 'dataguard_association_id'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        id=pulumi.get(__response__, 'id'),
        key=pulumi.get(__response__, 'key'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        peer_target_database_id=pulumi.get(__response__, 'peer_target_database_id'),
        role=pulumi.get(__response__, 'role'),
        state=pulumi.get(__response__, 'state'),
        target_database_id=pulumi.get(__response__, 'target_database_id'),
        time_created=pulumi.get(__response__, 'time_created'),
        tls_configs=pulumi.get(__response__, 'tls_configs')))
