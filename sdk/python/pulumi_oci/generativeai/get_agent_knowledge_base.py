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
    'GetAgentKnowledgeBaseResult',
    'AwaitableGetAgentKnowledgeBaseResult',
    'get_agent_knowledge_base',
    'get_agent_knowledge_base_output',
]

@pulumi.output_type
class GetAgentKnowledgeBaseResult:
    """
    A collection of values returned by getAgentKnowledgeBase.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, id=None, index_configs=None, knowledge_base_id=None, lifecycle_details=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if index_configs and not isinstance(index_configs, list):
            raise TypeError("Expected argument 'index_configs' to be a list")
        pulumi.set(__self__, "index_configs", index_configs)
        if knowledge_base_id and not isinstance(knowledge_base_id, str):
            raise TypeError("Expected argument 'knowledge_base_id' to be a str")
        pulumi.set(__self__, "knowledge_base_id", knowledge_base_id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
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
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, _builtins.str]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @_builtins.property
    @pulumi.getter
    def description(self) -> _builtins.str:
        """
        A description of the knowledge base.
        """
        return pulumi.get(self, "description")

    @_builtins.property
    @pulumi.getter(name="displayName")
    def display_name(self) -> _builtins.str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable.
        """
        return pulumi.get(self, "display_name")

    @_builtins.property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, _builtins.str]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledge base.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="indexConfigs")
    def index_configs(self) -> Sequence['outputs.GetAgentKnowledgeBaseIndexConfigResult']:
        """
        **IndexConfig**
        """
        return pulumi.get(self, "index_configs")

    @_builtins.property
    @pulumi.getter(name="knowledgeBaseId")
    def knowledge_base_id(self) -> _builtins.str:
        return pulumi.get(self, "knowledge_base_id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message that describes the current state of the knowledge base in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the knowledge base.
        """
        return pulumi.get(self, "state")

    @_builtins.property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, _builtins.str]:
        """
        System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @_builtins.property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> _builtins.str:
        """
        The date and time the knowledge base was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the knowledge base was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetAgentKnowledgeBaseResult(GetAgentKnowledgeBaseResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAgentKnowledgeBaseResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            index_configs=self.index_configs,
            knowledge_base_id=self.knowledge_base_id,
            lifecycle_details=self.lifecycle_details,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_agent_knowledge_base(knowledge_base_id: Optional[_builtins.str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAgentKnowledgeBaseResult:
    """
    This data source provides details about a specific Knowledge Base resource in Oracle Cloud Infrastructure Generative Ai Agent service.

    **GetKnowledgeBase**

    Gets information about a knowledge base.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_knowledge_base = oci.GenerativeAi.get_agent_knowledge_base(knowledge_base_id=test_knowledge_base_oci_generative_ai_agent_knowledge_base["id"])
    ```


    :param _builtins.str knowledge_base_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledge base.
    """
    __args__ = dict()
    __args__['knowledgeBaseId'] = knowledge_base_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:GenerativeAi/getAgentKnowledgeBase:getAgentKnowledgeBase', __args__, opts=opts, typ=GetAgentKnowledgeBaseResult).value

    return AwaitableGetAgentKnowledgeBaseResult(
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        id=pulumi.get(__ret__, 'id'),
        index_configs=pulumi.get(__ret__, 'index_configs'),
        knowledge_base_id=pulumi.get(__ret__, 'knowledge_base_id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_agent_knowledge_base_output(knowledge_base_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAgentKnowledgeBaseResult]:
    """
    This data source provides details about a specific Knowledge Base resource in Oracle Cloud Infrastructure Generative Ai Agent service.

    **GetKnowledgeBase**

    Gets information about a knowledge base.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_knowledge_base = oci.GenerativeAi.get_agent_knowledge_base(knowledge_base_id=test_knowledge_base_oci_generative_ai_agent_knowledge_base["id"])
    ```


    :param _builtins.str knowledge_base_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the knowledge base.
    """
    __args__ = dict()
    __args__['knowledgeBaseId'] = knowledge_base_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:GenerativeAi/getAgentKnowledgeBase:getAgentKnowledgeBase', __args__, opts=opts, typ=GetAgentKnowledgeBaseResult)
    return __ret__.apply(lambda __response__: GetAgentKnowledgeBaseResult(
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        id=pulumi.get(__response__, 'id'),
        index_configs=pulumi.get(__response__, 'index_configs'),
        knowledge_base_id=pulumi.get(__response__, 'knowledge_base_id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
