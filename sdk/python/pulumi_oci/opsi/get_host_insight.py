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

__all__ = [
    'GetHostInsightResult',
    'AwaitableGetHostInsightResult',
    'get_host_insight',
    'get_host_insight_output',
]

@pulumi.output_type
class GetHostInsightResult:
    """
    A collection of values returned by getHostInsight.
    """
    def __init__(__self__, compartment_id=None, compute_id=None, defined_tags=None, enterprise_manager_bridge_id=None, enterprise_manager_entity_display_name=None, enterprise_manager_entity_identifier=None, enterprise_manager_entity_name=None, enterprise_manager_entity_type=None, enterprise_manager_identifier=None, entity_source=None, exadata_insight_id=None, freeform_tags=None, host_display_name=None, host_insight_id=None, host_name=None, host_type=None, id=None, lifecycle_details=None, management_agent_id=None, platform_name=None, platform_type=None, platform_version=None, processor_count=None, state=None, status=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if compute_id and not isinstance(compute_id, str):
            raise TypeError("Expected argument 'compute_id' to be a str")
        pulumi.set(__self__, "compute_id", compute_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if enterprise_manager_bridge_id and not isinstance(enterprise_manager_bridge_id, str):
            raise TypeError("Expected argument 'enterprise_manager_bridge_id' to be a str")
        pulumi.set(__self__, "enterprise_manager_bridge_id", enterprise_manager_bridge_id)
        if enterprise_manager_entity_display_name and not isinstance(enterprise_manager_entity_display_name, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_display_name' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_display_name", enterprise_manager_entity_display_name)
        if enterprise_manager_entity_identifier and not isinstance(enterprise_manager_entity_identifier, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_identifier' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_identifier", enterprise_manager_entity_identifier)
        if enterprise_manager_entity_name and not isinstance(enterprise_manager_entity_name, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_name' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_name", enterprise_manager_entity_name)
        if enterprise_manager_entity_type and not isinstance(enterprise_manager_entity_type, str):
            raise TypeError("Expected argument 'enterprise_manager_entity_type' to be a str")
        pulumi.set(__self__, "enterprise_manager_entity_type", enterprise_manager_entity_type)
        if enterprise_manager_identifier and not isinstance(enterprise_manager_identifier, str):
            raise TypeError("Expected argument 'enterprise_manager_identifier' to be a str")
        pulumi.set(__self__, "enterprise_manager_identifier", enterprise_manager_identifier)
        if entity_source and not isinstance(entity_source, str):
            raise TypeError("Expected argument 'entity_source' to be a str")
        pulumi.set(__self__, "entity_source", entity_source)
        if exadata_insight_id and not isinstance(exadata_insight_id, str):
            raise TypeError("Expected argument 'exadata_insight_id' to be a str")
        pulumi.set(__self__, "exadata_insight_id", exadata_insight_id)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if host_display_name and not isinstance(host_display_name, str):
            raise TypeError("Expected argument 'host_display_name' to be a str")
        pulumi.set(__self__, "host_display_name", host_display_name)
        if host_insight_id and not isinstance(host_insight_id, str):
            raise TypeError("Expected argument 'host_insight_id' to be a str")
        pulumi.set(__self__, "host_insight_id", host_insight_id)
        if host_name and not isinstance(host_name, str):
            raise TypeError("Expected argument 'host_name' to be a str")
        pulumi.set(__self__, "host_name", host_name)
        if host_type and not isinstance(host_type, str):
            raise TypeError("Expected argument 'host_type' to be a str")
        pulumi.set(__self__, "host_type", host_type)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if management_agent_id and not isinstance(management_agent_id, str):
            raise TypeError("Expected argument 'management_agent_id' to be a str")
        pulumi.set(__self__, "management_agent_id", management_agent_id)
        if platform_name and not isinstance(platform_name, str):
            raise TypeError("Expected argument 'platform_name' to be a str")
        pulumi.set(__self__, "platform_name", platform_name)
        if platform_type and not isinstance(platform_type, str):
            raise TypeError("Expected argument 'platform_type' to be a str")
        pulumi.set(__self__, "platform_type", platform_type)
        if platform_version and not isinstance(platform_version, str):
            raise TypeError("Expected argument 'platform_version' to be a str")
        pulumi.set(__self__, "platform_version", platform_version)
        if processor_count and not isinstance(processor_count, int):
            raise TypeError("Expected argument 'processor_count' to be a int")
        pulumi.set(__self__, "processor_count", processor_count)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if status and not isinstance(status, str):
            raise TypeError("Expected argument 'status' to be a str")
        pulumi.set(__self__, "status", status)
        if system_tags and not isinstance(system_tags, dict):
            raise TypeError("Expected argument 'system_tags' to be a dict")
        pulumi.set(__self__, "system_tags", system_tags)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_updated and not isinstance(time_updated, str):
            raise TypeError("Expected argument 'time_updated' to be a str")
        pulumi.set(__self__, "time_updated", time_updated)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="computeId")
    def compute_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Compute Instance
        """
        return pulumi.get(self, "compute_id")

    @_builtins.property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter(name="enterpriseManagerBridgeId")
    def enterprise_manager_bridge_id(self) -> _builtins.str:
        """
        OPSI Enterprise Manager Bridge OCID
        """
        return pulumi.get(self, "enterprise_manager_bridge_id")

    @_builtins.property
    @pulumi.getter(name="enterpriseManagerEntityDisplayName")
    def enterprise_manager_entity_display_name(self) -> _builtins.str:
        """
        Enterprise Manager Entity Display Name
        """
        return pulumi.get(self, "enterprise_manager_entity_display_name")

    @_builtins.property
    @pulumi.getter(name="enterpriseManagerEntityIdentifier")
    def enterprise_manager_entity_identifier(self) -> _builtins.str:
        """
        Enterprise Manager Entity Unique Identifier
        """
        return pulumi.get(self, "enterprise_manager_entity_identifier")

    @_builtins.property
    @pulumi.getter(name="enterpriseManagerEntityName")
    def enterprise_manager_entity_name(self) -> _builtins.str:
        """
        Enterprise Manager Entity Name
        """
        return pulumi.get(self, "enterprise_manager_entity_name")

    @_builtins.property
    @pulumi.getter(name="enterpriseManagerEntityType")
    def enterprise_manager_entity_type(self) -> _builtins.str:
        """
        Enterprise Manager Entity Type
        """
        return pulumi.get(self, "enterprise_manager_entity_type")

    @_builtins.property
    @pulumi.getter(name="enterpriseManagerIdentifier")
    def enterprise_manager_identifier(self) -> _builtins.str:
        """
        Enterprise Manager Unique Identifier
        """
        return pulumi.get(self, "enterprise_manager_identifier")

    @_builtins.property
    @pulumi.getter(name="entitySource")
    def entity_source(self) -> _builtins.str:
        """
        Source of the host entity.
        """
        return pulumi.get(self, "entity_source")

    @_builtins.property
    @pulumi.getter(name="exadataInsightId")
    def exadata_insight_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Exadata insight.
        """
        return pulumi.get(self, "exadata_insight_id")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter(name="hostDisplayName")
    def host_display_name(self) -> _builtins.str:
        """
        The user-friendly name for the host. The name does not have to be unique.
        """
        return pulumi.get(self, "host_display_name")

    @_builtins.property
    @pulumi.getter(name="hostInsightId")
    def host_insight_id(self) -> _builtins.str:
        return pulumi.get(self, "host_insight_id")

    @_builtins.property
    @pulumi.getter(name="hostName")
    def host_name(self) -> _builtins.str:
        """
        The host name. The host name is unique amongst the hosts managed by the same management agent.
        """
        return pulumi.get(self, "host_name")

    @_builtins.property
    @pulumi.getter(name="hostType")
    def host_type(self) -> _builtins.str:
        """
        Ops Insights internal representation of the host type. Possible value is EXTERNAL-HOST.
        """
        return pulumi.get(self, "host_type")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the host insight resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter(name="managementAgentId")
    def management_agent_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Management Agent
        """
        return pulumi.get(self, "management_agent_id")

    @_builtins.property
    @pulumi.getter(name="platformName")
    def platform_name(self) -> _builtins.str:
        """
        Platform name.
        """
        return pulumi.get(self, "platform_name")

    @_builtins.property
    @pulumi.getter(name="platformType")
    def platform_type(self) -> _builtins.str:
        """
        Platform type. Supported platformType(s) for MACS-managed external host insight: [LINUX, SOLARIS, WINDOWS]. Supported platformType(s) for MACS-managed cloud host insight: [LINUX]. Supported platformType(s) for EM-managed external host insight: [LINUX, SOLARIS, SUNOS, ZLINUX, WINDOWS, AIX].
        """
        return pulumi.get(self, "platform_type")

    @_builtins.property
    @pulumi.getter(name="platformVersion")
    def platform_version(self) -> _builtins.str:
        """
        Platform version.
        """
        return pulumi.get(self, "platform_version")

    @_builtins.property
    @pulumi.getter(name="processorCount")
    def processor_count(self) -> _builtins.int:
        return pulumi.get(self, "processor_count")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the host.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter
    def status(self) -> _builtins.str:
        """
        Indicates the status of a host insight in Operations Insights
        """
        return pulumi.get(self, "status")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The time the the host insight was first enabled. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The time the host insight was updated. An RFC3339 formatted datetime string
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetHostInsightResult(GetHostInsightResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetHostInsightResult(
            compartment_id=self.compartment_id,
            compute_id=self.compute_id,
            defined_tags=self.defined_tags,
            enterprise_manager_bridge_id=self.enterprise_manager_bridge_id,
            enterprise_manager_entity_display_name=self.enterprise_manager_entity_display_name,
            enterprise_manager_entity_identifier=self.enterprise_manager_entity_identifier,
            enterprise_manager_entity_name=self.enterprise_manager_entity_name,
            enterprise_manager_entity_type=self.enterprise_manager_entity_type,
            enterprise_manager_identifier=self.enterprise_manager_identifier,
            entity_source=self.entity_source,
            exadata_insight_id=self.exadata_insight_id,
            freeform_tags=self.freeform_tags,
            host_display_name=self.host_display_name,
            host_insight_id=self.host_insight_id,
            host_name=self.host_name,
            host_type=self.host_type,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            management_agent_id=self.management_agent_id,
            platform_name=self.platform_name,
            platform_type=self.platform_type,
            platform_version=self.platform_version,
            processor_count=self.processor_count,
            state=self.state,
            status=self.status,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_host_insight(host_insight_id: Optional[_builtins.str] = None,
                     opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetHostInsightResult:
    """
    This data source provides details about a specific Host Insight resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of a host insight.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_host_insight = oci.Opsi.get_host_insight(host_insight_id=test_host_insight_oci_opsi_host_insight["id"])
    ```


    :param _builtins.str host_insight_id: Unique host insight identifier
    """
    __args__ = dict()
    __args__['hostInsightId'] = host_insight_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Opsi/getHostInsight:getHostInsight', __args__, opts=opts, typ=GetHostInsightResult).value

    return AwaitableGetHostInsightResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        compute_id=pulumi.get(__ret__, 'compute_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        enterprise_manager_bridge_id=pulumi.get(__ret__, 'enterprise_manager_bridge_id'),
        enterprise_manager_entity_display_name=pulumi.get(__ret__, 'enterprise_manager_entity_display_name'),
        enterprise_manager_entity_identifier=pulumi.get(__ret__, 'enterprise_manager_entity_identifier'),
        enterprise_manager_entity_name=pulumi.get(__ret__, 'enterprise_manager_entity_name'),
        enterprise_manager_entity_type=pulumi.get(__ret__, 'enterprise_manager_entity_type'),
        enterprise_manager_identifier=pulumi.get(__ret__, 'enterprise_manager_identifier'),
        entity_source=pulumi.get(__ret__, 'entity_source'),
        exadata_insight_id=pulumi.get(__ret__, 'exadata_insight_id'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        host_display_name=pulumi.get(__ret__, 'host_display_name'),
        host_insight_id=pulumi.get(__ret__, 'host_insight_id'),
        host_name=pulumi.get(__ret__, 'host_name'),
        host_type=pulumi.get(__ret__, 'host_type'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        management_agent_id=pulumi.get(__ret__, 'management_agent_id'),
        platform_name=pulumi.get(__ret__, 'platform_name'),
        platform_type=pulumi.get(__ret__, 'platform_type'),
        platform_version=pulumi.get(__ret__, 'platform_version'),
        processor_count=pulumi.get(__ret__, 'processor_count'),
        state=pulumi.get(__ret__, 'state'),
        status=pulumi.get(__ret__, 'status'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_host_insight_output(host_insight_id: Optional[pulumi.Input[_builtins.str]] = None,
                            opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetHostInsightResult]:
    """
    This data source provides details about a specific Host Insight resource in Oracle Cloud Infrastructure Opsi service.

    Gets details of a host insight.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_host_insight = oci.Opsi.get_host_insight(host_insight_id=test_host_insight_oci_opsi_host_insight["id"])
    ```


    :param _builtins.str host_insight_id: Unique host insight identifier
    """
    __args__ = dict()
    __args__['hostInsightId'] = host_insight_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Opsi/getHostInsight:getHostInsight', __args__, opts=opts, typ=GetHostInsightResult)
    return __ret__.apply(lambda __response__: GetHostInsightResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        compute_id=pulumi.get(__response__, 'compute_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        enterprise_manager_bridge_id=pulumi.get(__response__, 'enterprise_manager_bridge_id'),
        enterprise_manager_entity_display_name=pulumi.get(__response__, 'enterprise_manager_entity_display_name'),
        enterprise_manager_entity_identifier=pulumi.get(__response__, 'enterprise_manager_entity_identifier'),
        enterprise_manager_entity_name=pulumi.get(__response__, 'enterprise_manager_entity_name'),
        enterprise_manager_entity_type=pulumi.get(__response__, 'enterprise_manager_entity_type'),
        enterprise_manager_identifier=pulumi.get(__response__, 'enterprise_manager_identifier'),
        entity_source=pulumi.get(__response__, 'entity_source'),
        exadata_insight_id=pulumi.get(__response__, 'exadata_insight_id'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        host_display_name=pulumi.get(__response__, 'host_display_name'),
        host_insight_id=pulumi.get(__response__, 'host_insight_id'),
        host_name=pulumi.get(__response__, 'host_name'),
        host_type=pulumi.get(__response__, 'host_type'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        management_agent_id=pulumi.get(__response__, 'management_agent_id'),
        platform_name=pulumi.get(__response__, 'platform_name'),
        platform_type=pulumi.get(__response__, 'platform_type'),
        platform_version=pulumi.get(__response__, 'platform_version'),
        processor_count=pulumi.get(__response__, 'processor_count'),
        state=pulumi.get(__response__, 'state'),
        status=pulumi.get(__response__, 'status'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
