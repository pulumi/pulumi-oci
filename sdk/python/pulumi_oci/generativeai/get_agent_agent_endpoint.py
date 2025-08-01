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
    'GetAgentAgentEndpointResult',
    'AwaitableGetAgentAgentEndpointResult',
    'get_agent_agent_endpoint',
    'get_agent_agent_endpoint_output',
]

@pulumi.output_type
class GetAgentAgentEndpointResult:
    """
    A collection of values returned by getAgentAgentEndpoint.
    """
    def __init__(__self__, agent_endpoint_id=None, agent_id=None, compartment_id=None, content_moderation_configs=None, defined_tags=None, description=None, display_name=None, freeform_tags=None, guardrail_configs=None, human_input_configs=None, id=None, lifecycle_details=None, metadata=None, output_configs=None, session_configs=None, should_enable_citation=None, should_enable_multi_language=None, should_enable_session=None, should_enable_trace=None, state=None, system_tags=None, time_created=None, time_updated=None):
        if agent_endpoint_id and not isinstance(agent_endpoint_id, str):
            raise TypeError("Expected argument 'agent_endpoint_id' to be a str")
        pulumi.set(__self__, "agent_endpoint_id", agent_endpoint_id)
        if agent_id and not isinstance(agent_id, str):
            raise TypeError("Expected argument 'agent_id' to be a str")
        pulumi.set(__self__, "agent_id", agent_id)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if content_moderation_configs and not isinstance(content_moderation_configs, list):
            raise TypeError("Expected argument 'content_moderation_configs' to be a list")
        pulumi.set(__self__, "content_moderation_configs", content_moderation_configs)
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
        if guardrail_configs and not isinstance(guardrail_configs, list):
            raise TypeError("Expected argument 'guardrail_configs' to be a list")
        pulumi.set(__self__, "guardrail_configs", guardrail_configs)
        if human_input_configs and not isinstance(human_input_configs, list):
            raise TypeError("Expected argument 'human_input_configs' to be a list")
        pulumi.set(__self__, "human_input_configs", human_input_configs)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if lifecycle_details and not isinstance(lifecycle_details, str):
            raise TypeError("Expected argument 'lifecycle_details' to be a str")
        pulumi.set(__self__, "lifecycle_details", lifecycle_details)
        if metadata and not isinstance(metadata, dict):
            raise TypeError("Expected argument 'metadata' to be a dict")
        pulumi.set(__self__, "metadata", metadata)
        if output_configs and not isinstance(output_configs, list):
            raise TypeError("Expected argument 'output_configs' to be a list")
        pulumi.set(__self__, "output_configs", output_configs)
        if session_configs and not isinstance(session_configs, list):
            raise TypeError("Expected argument 'session_configs' to be a list")
        pulumi.set(__self__, "session_configs", session_configs)
        if should_enable_citation and not isinstance(should_enable_citation, bool):
            raise TypeError("Expected argument 'should_enable_citation' to be a bool")
        pulumi.set(__self__, "should_enable_citation", should_enable_citation)
        if should_enable_multi_language and not isinstance(should_enable_multi_language, bool):
            raise TypeError("Expected argument 'should_enable_multi_language' to be a bool")
        pulumi.set(__self__, "should_enable_multi_language", should_enable_multi_language)
        if should_enable_session and not isinstance(should_enable_session, bool):
            raise TypeError("Expected argument 'should_enable_session' to be a bool")
        pulumi.set(__self__, "should_enable_session", should_enable_session)
        if should_enable_trace and not isinstance(should_enable_trace, bool):
            raise TypeError("Expected argument 'should_enable_trace' to be a bool")
        pulumi.set(__self__, "should_enable_trace", should_enable_trace)
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
    @pulumi.getter(name="agentEndpointId")
    def agent_endpoint_id(self) -> _builtins.str:
        return pulumi.get(self, "agent_endpoint_id")

    @_builtins.property
    @pulumi.getter(name="agentId")
    def agent_id(self) -> _builtins.str:
        """
        The OCID of the agent that this endpoint is associated with.
        """
        return pulumi.get(self, "agent_id")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="contentModerationConfigs")
    def content_moderation_configs(self) -> Sequence['outputs.GetAgentAgentEndpointContentModerationConfigResult']:
        """
        The configuration details about whether to apply the content moderation feature to input and output. Content moderation removes toxic and biased content from responses. It is recommended to use content moderation.
        """
        return pulumi.get(self, "content_moderation_configs")

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
        An optional description of the endpoint.
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
    @pulumi.getter(name="guardrailConfigs")
    def guardrail_configs(self) -> Sequence['outputs.GetAgentAgentEndpointGuardrailConfigResult']:
        """
        The configuration details about whether to apply the guardrail checks to input and output.
        """
        return pulumi.get(self, "guardrail_configs")

    @_builtins.property
    @pulumi.getter(name="humanInputConfigs")
    def human_input_configs(self) -> Sequence['outputs.GetAgentAgentEndpointHumanInputConfigResult']:
        """
        Human Input Configuration for an AgentEndpoint.
        """
        return pulumi.get(self, "human_input_configs")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="lifecycleDetails")
    def lifecycle_details(self) -> _builtins.str:
        """
        A message that describes the current state of the endpoint in more detail. For example, can be used to provide actionable information for a resource in the Failed state.
        """
        return pulumi.get(self, "lifecycle_details")

    @_builtins.property
    @pulumi.getter
    def metadata(self) -> Mapping[str, _builtins.str]:
        """
        Key-value pairs to allow additional configurations.
        """
        return pulumi.get(self, "metadata")

    @_builtins.property
    @pulumi.getter(name="outputConfigs")
    def output_configs(self) -> Sequence['outputs.GetAgentAgentEndpointOutputConfigResult']:
        """
        Configuration to store results generated by agent.
        """
        return pulumi.get(self, "output_configs")

    @_builtins.property
    @pulumi.getter(name="sessionConfigs")
    def session_configs(self) -> Sequence['outputs.GetAgentAgentEndpointSessionConfigResult']:
        """
        Session Configuration on AgentEndpoint.
        """
        return pulumi.get(self, "session_configs")

    @_builtins.property
    @pulumi.getter(name="shouldEnableCitation")
    def should_enable_citation(self) -> _builtins.bool:
        """
        Whether to show citations in the chat result.
        """
        return pulumi.get(self, "should_enable_citation")

    @_builtins.property
    @pulumi.getter(name="shouldEnableMultiLanguage")
    def should_enable_multi_language(self) -> _builtins.bool:
        """
        Whether to enable multi-language for chat.
        """
        return pulumi.get(self, "should_enable_multi_language")

    @_builtins.property
    @pulumi.getter(name="shouldEnableSession")
    def should_enable_session(self) -> _builtins.bool:
        """
        Whether or not to enable Session-based chat.
        """
        return pulumi.get(self, "should_enable_session")

    @_builtins.property
    @pulumi.getter(name="shouldEnableTrace")
    def should_enable_trace(self) -> _builtins.bool:
        """
        Whether to show traces in the chat result.
        """
        return pulumi.get(self, "should_enable_trace")

    @_builtins.property
    @pulumi.getter
    def state(self) -> _builtins.str:
        """
        The current state of the endpoint.
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
        The date and time the AgentEndpoint was created, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_created")

    @_builtins.property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> _builtins.str:
        """
        The date and time the endpoint was updated, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
        """
        return pulumi.get(self, "time_updated")


class AwaitableGetAgentAgentEndpointResult(GetAgentAgentEndpointResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetAgentAgentEndpointResult(
            agent_endpoint_id=self.agent_endpoint_id,
            agent_id=self.agent_id,
            compartment_id=self.compartment_id,
            content_moderation_configs=self.content_moderation_configs,
            defined_tags=self.defined_tags,
            description=self.description,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            guardrail_configs=self.guardrail_configs,
            human_input_configs=self.human_input_configs,
            id=self.id,
            lifecycle_details=self.lifecycle_details,
            metadata=self.metadata,
            output_configs=self.output_configs,
            session_configs=self.session_configs,
            should_enable_citation=self.should_enable_citation,
            should_enable_multi_language=self.should_enable_multi_language,
            should_enable_session=self.should_enable_session,
            should_enable_trace=self.should_enable_trace,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated)


def get_agent_agent_endpoint(agent_endpoint_id: Optional[_builtins.str] = None,
                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetAgentAgentEndpointResult:
    """
    This data source provides details about a specific Agent Endpoint resource in Oracle Cloud Infrastructure Generative Ai Agent service.

    Gets information about an endpoint.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_agent_endpoint = oci.GenerativeAi.get_agent_agent_endpoint(agent_endpoint_id=test_agent_endpoint_oci_generative_ai_agent_agent_endpoint["id"])
    ```


    :param _builtins.str agent_endpoint_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
    """
    __args__ = dict()
    __args__['agentEndpointId'] = agent_endpoint_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:GenerativeAi/getAgentAgentEndpoint:getAgentAgentEndpoint', __args__, opts=opts, typ=GetAgentAgentEndpointResult).value

    return AwaitableGetAgentAgentEndpointResult(
        agent_endpoint_id=pulumi.get(__ret__, 'agent_endpoint_id'),
        agent_id=pulumi.get(__ret__, 'agent_id'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        content_moderation_configs=pulumi.get(__ret__, 'content_moderation_configs'),
        defined_tags=pulumi.get(__ret__, 'defined_tags'),
        description=pulumi.get(__ret__, 'description'),
        display_name=pulumi.get(__ret__, 'display_name'),
        freeform_tags=pulumi.get(__ret__, 'freeform_tags'),
        guardrail_configs=pulumi.get(__ret__, 'guardrail_configs'),
        human_input_configs=pulumi.get(__ret__, 'human_input_configs'),
        id=pulumi.get(__ret__, 'id'),
        lifecycle_details=pulumi.get(__ret__, 'lifecycle_details'),
        metadata=pulumi.get(__ret__, 'metadata'),
        output_configs=pulumi.get(__ret__, 'output_configs'),
        session_configs=pulumi.get(__ret__, 'session_configs'),
        should_enable_citation=pulumi.get(__ret__, 'should_enable_citation'),
        should_enable_multi_language=pulumi.get(__ret__, 'should_enable_multi_language'),
        should_enable_session=pulumi.get(__ret__, 'should_enable_session'),
        should_enable_trace=pulumi.get(__ret__, 'should_enable_trace'),
        state=pulumi.get(__ret__, 'state'),
        system_tags=pulumi.get(__ret__, 'system_tags'),
        time_created=pulumi.get(__ret__, 'time_created'),
        time_updated=pulumi.get(__ret__, 'time_updated'))
def get_agent_agent_endpoint_output(agent_endpoint_id: Optional[pulumi.Input[_builtins.str]] = None,
                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetAgentAgentEndpointResult]:
    """
    This data source provides details about a specific Agent Endpoint resource in Oracle Cloud Infrastructure Generative Ai Agent service.

    Gets information about an endpoint.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_agent_endpoint = oci.GenerativeAi.get_agent_agent_endpoint(agent_endpoint_id=test_agent_endpoint_oci_generative_ai_agent_agent_endpoint["id"])
    ```


    :param _builtins.str agent_endpoint_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the endpoint.
    """
    __args__ = dict()
    __args__['agentEndpointId'] = agent_endpoint_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:GenerativeAi/getAgentAgentEndpoint:getAgentAgentEndpoint', __args__, opts=opts, typ=GetAgentAgentEndpointResult)
    return __ret__.apply(lambda __response__: GetAgentAgentEndpointResult(
        agent_endpoint_id=pulumi.get(__response__, 'agent_endpoint_id'),
        agent_id=pulumi.get(__response__, 'agent_id'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        content_moderation_configs=pulumi.get(__response__, 'content_moderation_configs'),
        defined_tags=pulumi.get(__response__, 'defined_tags'),
        description=pulumi.get(__response__, 'description'),
        display_name=pulumi.get(__response__, 'display_name'),
        freeform_tags=pulumi.get(__response__, 'freeform_tags'),
        guardrail_configs=pulumi.get(__response__, 'guardrail_configs'),
        human_input_configs=pulumi.get(__response__, 'human_input_configs'),
        id=pulumi.get(__response__, 'id'),
        lifecycle_details=pulumi.get(__response__, 'lifecycle_details'),
        metadata=pulumi.get(__response__, 'metadata'),
        output_configs=pulumi.get(__response__, 'output_configs'),
        session_configs=pulumi.get(__response__, 'session_configs'),
        should_enable_citation=pulumi.get(__response__, 'should_enable_citation'),
        should_enable_multi_language=pulumi.get(__response__, 'should_enable_multi_language'),
        should_enable_session=pulumi.get(__response__, 'should_enable_session'),
        should_enable_trace=pulumi.get(__response__, 'should_enable_trace'),
        state=pulumi.get(__response__, 'state'),
        system_tags=pulumi.get(__response__, 'system_tags'),
        time_created=pulumi.get(__response__, 'time_created'),
        time_updated=pulumi.get(__response__, 'time_updated')))
