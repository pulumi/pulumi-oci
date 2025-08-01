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
    'GetCloudVmClusterIormConfigResult',
    'AwaitableGetCloudVmClusterIormConfigResult',
    'get_cloud_vm_cluster_iorm_config',
    'get_cloud_vm_cluster_iorm_config_output',
]

@pulumi.output_type
class GetCloudVmClusterIormConfigResult:
    """
    A collection of values returned by getCloudVmClusterIormConfig.
    """
    def __init__(__self__, cloud_vm_cluster_id=None, db_plans=None, id=None, lifecycle_details=None, objective=None, state=None):
        if cloud_vm_cluster_id and not isinstance(cloud_vm_cluster_id, str):
            raise TypeError("Expected argument 'cloud_vm_cluster_id' to be a str")
        pulumi.set(__self__, "cloud_vm_cluster_id", cloud_vm_cluster_id)
        if db_plans and not isinstance(db_plans, list):
            raise TypeError("Expected argument 'db_plans' to be a list")
        pulumi.set(__self__, "db_plans", db_plans)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if objective and not isinstance(objective, str):
            raise TypeError("Expected argument 'objective' to be a str")
        pulumi.set(__self__, "objective", objective)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)

    @_builtins.property
    @pulumi.getter(name="cloudVmClusterId")
    def cloud_vm_cluster_id(self) -> _builtins.str:
        return pulumi.get(self, "cloud_vm_cluster_id")

    @_builtins.property
    @pulumi.getter(name="dbPlans")
    def db_plans(self) -> Sequence['outputs.GetCloudVmClusterIormConfigDbPlanResult']:
        """
        An array of IORM settings for all the database in the cloud vm cluster.
        """
        return pulumi.get(self, "db_plans")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        Additional information about the current `lifecycleState`.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def objective(self) -> _builtins.str:
        """
        The current value for the IORM objective. The default is `AUTO`.
        """
        return pulumi.get(self, "objective")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of IORM configuration for the cloud vm cluster.
        """
        return pulumi.get(self, "state")


class AwaitableGetCloudVmClusterIormConfigResult(GetCloudVmClusterIormConfigResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetCloudVmClusterIormConfigResult(
            cloud_vm_cluster_id=self.cloud_vm_cluster_id,
            db_plans=self.db_plans,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            objective=self.objective,
            state=self.state)


def get_cloud_vm_cluster_iorm_config(cloud_vm_cluster_id: Optional[_builtins.str] = None,
                                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetCloudVmClusterIormConfigResult:
    """
    This data source provides details about a specific Cloud Vm Cluster Iorm Config resource in Oracle Cloud Infrastructure Database service.

    Gets the IORM configuration settings for the specified Cloud Vm Cluster.
    All Exadata service instances have default IORM settings.

    The [GetCloudVmClusterIormConfig](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/GetCloudVmClusterIormConfig/) API is used for this operation with Cloud Vm Cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cloud_vm_cluster_iorm_config = oci.Database.get_cloud_vm_cluster_iorm_config(cloud_vm_cluster_id=test_cloud_vm_cluster["id"])
    ```


    :param _builtins.str cloud_vm_cluster_id: The cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['cloudVmClusterId'] = cloud_vm_cluster_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Database/getCloudVmClusterIormConfig:getCloudVmClusterIormConfig', __args__, opts=opts, typ=GetCloudVmClusterIormConfigResult).value

    return AwaitableGetCloudVmClusterIormConfigResult(
        cloud_vm_cluster_id=pulumi.get(__ret__, 'cloud_vm_cluster_id'),
        db_plans=pulumi.get(__ret__, 'db_plans'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        objective=pulumi.get(__ret__, 'objective'),
        state=pulumi.get(__ret__, 'state'))
def get_cloud_vm_cluster_iorm_config_output(cloud_vm_cluster_id: Optional[pulumi.Input[_builtins.str]] = None,
                                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetCloudVmClusterIormConfigResult]:
    """
    This data source provides details about a specific Cloud Vm Cluster Iorm Config resource in Oracle Cloud Infrastructure Database service.

    Gets the IORM configuration settings for the specified Cloud Vm Cluster.
    All Exadata service instances have default IORM settings.

    The [GetCloudVmClusterIormConfig](https://docs.cloud.oracle.com/iaas/api/#/en/database/latest/CloudVmCluster/GetCloudVmClusterIormConfig/) API is used for this operation with Cloud Vm Cluster.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_cloud_vm_cluster_iorm_config = oci.Database.get_cloud_vm_cluster_iorm_config(cloud_vm_cluster_id=test_cloud_vm_cluster["id"])
    ```


    :param _builtins.str cloud_vm_cluster_id: The cluster [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
    """
    __args__ = dict()
    __args__['cloudVmClusterId'] = cloud_vm_cluster_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Database/getCloudVmClusterIormConfig:getCloudVmClusterIormConfig', __args__, opts=opts, typ=GetCloudVmClusterIormConfigResult)
    return __ret__.apply(lambda __response__: GetCloudVmClusterIormConfigResult(
        cloud_vm_cluster_id=pulumi.get(__response__, 'cloud_vm_cluster_id'),
        db_plans=pulumi.get(__response__, 'db_plans'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        objective=pulumi.get(__response__, 'objective'),
        state=pulumi.get(__response__, 'state')))
