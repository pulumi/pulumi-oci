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
from ._inputs import *

__all__ = ['PathAnalysiArgs', 'PathAnalysi']

@pulumi.input_type
class PathAnalysiArgs:
    def __init__(__self__, *,
                 type: pulumi.Input[_builtins.str],
                 cache_control: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 destination_endpoint: Optional[pulumi.Input['PathAnalysiDestinationEndpointArgs']] = None,
                 path_analyzer_test_id: Optional[pulumi.Input[_builtins.str]] = None,
                 protocol: Optional[pulumi.Input[_builtins.int]] = None,
                 protocol_parameters: Optional[pulumi.Input['PathAnalysiProtocolParametersArgs']] = None,
                 query_options: Optional[pulumi.Input['PathAnalysiQueryOptionsArgs']] = None,
                 source_endpoint: Optional[pulumi.Input['PathAnalysiSourceEndpointArgs']] = None):
        """
        The set of arguments for constructing a PathAnalysi resource.
        :param pulumi.Input[_builtins.str] type: The type of the `PathAnalysis` query.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        :param pulumi.Input[_builtins.str] cache_control: The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        :param pulumi.Input[_builtins.str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        :param pulumi.Input['PathAnalysiDestinationEndpointArgs'] destination_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] path_analyzer_test_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.int] protocol: The IP protocol to used for the path analysis.
        :param pulumi.Input['PathAnalysiProtocolParametersArgs'] protocol_parameters: Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        :param pulumi.Input['PathAnalysiQueryOptionsArgs'] query_options: Defines the query options required for a `PathAnalyzerTest` resource.
        :param pulumi.Input['PathAnalysiSourceEndpointArgs'] source_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        pulumi.set(__self__, "type", type)
        if cache_control is not None:
            pulumi.set(__self__, "cache_control", cache_control)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if destination_endpoint is not None:
            pulumi.set(__self__, "destination_endpoint", destination_endpoint)
        if path_analyzer_test_id is not None:
            pulumi.set(__self__, "path_analyzer_test_id", path_analyzer_test_id)
        if protocol is not None:
            pulumi.set(__self__, "protocol", protocol)
        if protocol_parameters is not None:
            pulumi.set(__self__, "protocol_parameters", protocol_parameters)
        if query_options is not None:
            pulumi.set(__self__, "query_options", query_options)
        if source_endpoint is not None:
            pulumi.set(__self__, "source_endpoint", source_endpoint)

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Input[_builtins.str]:
        """
        The type of the `PathAnalysis` query.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: pulumi.Input[_builtins.str]):
        pulumi.set(self, "type", value)

    @_builtins.property
    @pulumi.getter(name="cacheControl")
    def cache_control(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        """
        return pulumi.get(self, "cache_control")

    @cache_control.setter
    def cache_control(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "cache_control", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="destinationEndpoint")
    def destination_endpoint(self) -> Optional[pulumi.Input['PathAnalysiDestinationEndpointArgs']]:
        """
        Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "destination_endpoint")

    @destination_endpoint.setter
    def destination_endpoint(self, value: Optional[pulumi.Input['PathAnalysiDestinationEndpointArgs']]):
        pulumi.set(self, "destination_endpoint", value)

    @_builtins.property
    @pulumi.getter(name="pathAnalyzerTestId")
    def path_analyzer_test_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "path_analyzer_test_id")

    @path_analyzer_test_id.setter
    def path_analyzer_test_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "path_analyzer_test_id", value)

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> Optional[pulumi.Input[_builtins.int]]:
        """
        The IP protocol to used for the path analysis.
        """
        return pulumi.get(self, "protocol")

    @protocol.setter
    def protocol(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "protocol", value)

    @_builtins.property
    @pulumi.getter(name="protocolParameters")
    def protocol_parameters(self) -> Optional[pulumi.Input['PathAnalysiProtocolParametersArgs']]:
        """
        Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "protocol_parameters")

    @protocol_parameters.setter
    def protocol_parameters(self, value: Optional[pulumi.Input['PathAnalysiProtocolParametersArgs']]):
        pulumi.set(self, "protocol_parameters", value)

    @_builtins.property
    @pulumi.getter(name="queryOptions")
    def query_options(self) -> Optional[pulumi.Input['PathAnalysiQueryOptionsArgs']]:
        """
        Defines the query options required for a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "query_options")

    @query_options.setter
    def query_options(self, value: Optional[pulumi.Input['PathAnalysiQueryOptionsArgs']]):
        pulumi.set(self, "query_options", value)

    @_builtins.property
    @pulumi.getter(name="sourceEndpoint")
    def source_endpoint(self) -> Optional[pulumi.Input['PathAnalysiSourceEndpointArgs']]:
        """
        Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "source_endpoint")

    @source_endpoint.setter
    def source_endpoint(self, value: Optional[pulumi.Input['PathAnalysiSourceEndpointArgs']]):
        pulumi.set(self, "source_endpoint", value)


@pulumi.input_type
class _PathAnalysiState:
    def __init__(__self__, *,
                 cache_control: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 destination_endpoint: Optional[pulumi.Input['PathAnalysiDestinationEndpointArgs']] = None,
                 path_analyzer_test_id: Optional[pulumi.Input[_builtins.str]] = None,
                 protocol: Optional[pulumi.Input[_builtins.int]] = None,
                 protocol_parameters: Optional[pulumi.Input['PathAnalysiProtocolParametersArgs']] = None,
                 query_options: Optional[pulumi.Input['PathAnalysiQueryOptionsArgs']] = None,
                 source_endpoint: Optional[pulumi.Input['PathAnalysiSourceEndpointArgs']] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None):
        """
        Input properties used for looking up and filtering PathAnalysi resources.
        :param pulumi.Input[_builtins.str] cache_control: The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        :param pulumi.Input[_builtins.str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        :param pulumi.Input['PathAnalysiDestinationEndpointArgs'] destination_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] path_analyzer_test_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.int] protocol: The IP protocol to used for the path analysis.
        :param pulumi.Input['PathAnalysiProtocolParametersArgs'] protocol_parameters: Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        :param pulumi.Input['PathAnalysiQueryOptionsArgs'] query_options: Defines the query options required for a `PathAnalyzerTest` resource.
        :param pulumi.Input['PathAnalysiSourceEndpointArgs'] source_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] type: The type of the `PathAnalysis` query.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        if cache_control is not None:
            pulumi.set(__self__, "cache_control", cache_control)
        if compartment_id is not None:
            pulumi.set(__self__, "compartment_id", compartment_id)
        if destination_endpoint is not None:
            pulumi.set(__self__, "destination_endpoint", destination_endpoint)
        if path_analyzer_test_id is not None:
            pulumi.set(__self__, "path_analyzer_test_id", path_analyzer_test_id)
        if protocol is not None:
            pulumi.set(__self__, "protocol", protocol)
        if protocol_parameters is not None:
            pulumi.set(__self__, "protocol_parameters", protocol_parameters)
        if query_options is not None:
            pulumi.set(__self__, "query_options", query_options)
        if source_endpoint is not None:
            pulumi.set(__self__, "source_endpoint", source_endpoint)
        if type is not None:
            pulumi.set(__self__, "type", type)

    @_builtins.property
    @pulumi.getter(name="cacheControl")
    def cache_control(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        """
        return pulumi.get(self, "cache_control")

    @cache_control.setter
    def cache_control(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "cache_control", value)

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @compartment_id.setter
    def compartment_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "compartment_id", value)

    @_builtins.property
    @pulumi.getter(name="destinationEndpoint")
    def destination_endpoint(self) -> Optional[pulumi.Input['PathAnalysiDestinationEndpointArgs']]:
        """
        Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "destination_endpoint")

    @destination_endpoint.setter
    def destination_endpoint(self, value: Optional[pulumi.Input['PathAnalysiDestinationEndpointArgs']]):
        pulumi.set(self, "destination_endpoint", value)

    @_builtins.property
    @pulumi.getter(name="pathAnalyzerTestId")
    def path_analyzer_test_id(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "path_analyzer_test_id")

    @path_analyzer_test_id.setter
    def path_analyzer_test_id(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "path_analyzer_test_id", value)

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> Optional[pulumi.Input[_builtins.int]]:
        """
        The IP protocol to used for the path analysis.
        """
        return pulumi.get(self, "protocol")

    @protocol.setter
    def protocol(self, value: Optional[pulumi.Input[_builtins.int]]):
        pulumi.set(self, "protocol", value)

    @_builtins.property
    @pulumi.getter(name="protocolParameters")
    def protocol_parameters(self) -> Optional[pulumi.Input['PathAnalysiProtocolParametersArgs']]:
        """
        Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "protocol_parameters")

    @protocol_parameters.setter
    def protocol_parameters(self, value: Optional[pulumi.Input['PathAnalysiProtocolParametersArgs']]):
        pulumi.set(self, "protocol_parameters", value)

    @_builtins.property
    @pulumi.getter(name="queryOptions")
    def query_options(self) -> Optional[pulumi.Input['PathAnalysiQueryOptionsArgs']]:
        """
        Defines the query options required for a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "query_options")

    @query_options.setter
    def query_options(self, value: Optional[pulumi.Input['PathAnalysiQueryOptionsArgs']]):
        pulumi.set(self, "query_options", value)

    @_builtins.property
    @pulumi.getter(name="sourceEndpoint")
    def source_endpoint(self) -> Optional[pulumi.Input['PathAnalysiSourceEndpointArgs']]:
        """
        Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "source_endpoint")

    @source_endpoint.setter
    def source_endpoint(self, value: Optional[pulumi.Input['PathAnalysiSourceEndpointArgs']]):
        pulumi.set(self, "source_endpoint", value)

    @_builtins.property
    @pulumi.getter
    def type(self) -> Optional[pulumi.Input[_builtins.str]]:
        """
        The type of the `PathAnalysis` query.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "type")

    @type.setter
    def type(self, value: Optional[pulumi.Input[_builtins.str]]):
        pulumi.set(self, "type", value)


@pulumi.type_token("oci:VnMonitoring/pathAnalysi:PathAnalysi")
class PathAnalysi(pulumi.CustomResource):
    @overload
    def __init__(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cache_control: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 destination_endpoint: Optional[pulumi.Input[Union['PathAnalysiDestinationEndpointArgs', 'PathAnalysiDestinationEndpointArgsDict']]] = None,
                 path_analyzer_test_id: Optional[pulumi.Input[_builtins.str]] = None,
                 protocol: Optional[pulumi.Input[_builtins.int]] = None,
                 protocol_parameters: Optional[pulumi.Input[Union['PathAnalysiProtocolParametersArgs', 'PathAnalysiProtocolParametersArgsDict']]] = None,
                 query_options: Optional[pulumi.Input[Union['PathAnalysiQueryOptionsArgs', 'PathAnalysiQueryOptionsArgsDict']]] = None,
                 source_endpoint: Optional[pulumi.Input[Union['PathAnalysiSourceEndpointArgs', 'PathAnalysiSourceEndpointArgsDict']]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        """
        This resource provides the Path Analysi resource in Oracle Cloud Infrastructure Vn Monitoring service.

        Use this method to initiate a [Network Path Analyzer](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/path_analyzer.htm) analysis. This method returns
        an opc-work-request-id, and you can poll the status of the work request until it either fails or succeeds.

        If the work request status is successful, use [ListWorkRequestResults](https://docs.cloud.oracle.com/iaas/api/#/en/VnConfigAdvisor/latest/WorkRequestResult/ListWorkRequestResults)
        with the work request ID to ask for the successful analysis results. If the work request status is failed, use
        [ListWorkRequestErrors](https://docs.cloud.oracle.com/iaas/api/#/en/VnConfigAdvisor/latest/WorkRequestError/ListWorkRequestErrors)
        with the work request ID to ask for the analysis failure information. The information
        returned from either of these methods can be used to build a final report.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_path_analysi = oci.vnmonitoring.PathAnalysi("test_path_analysi",
            type=path_analysi_type,
            cache_control=path_analysi_cache_control,
            compartment_id=compartment_id,
            destination_endpoint={
                "type": path_analysi_destination_endpoint_type,
                "address": path_analysi_destination_endpoint_address,
                "instance_id": test_instance["id"],
                "listener_id": test_listener["id"],
                "load_balancer_id": test_load_balancer["id"],
                "network_load_balancer_id": test_network_load_balancer["id"],
                "subnet_id": test_subnet["id"],
                "vlan_id": test_vlan["id"],
                "vnic_id": test_vnic_attachment["id"],
            },
            path_analyzer_test_id=test_path_analyzer_test["id"],
            protocol=path_analysi_protocol,
            protocol_parameters={
                "type": path_analysi_protocol_parameters_type,
                "destination_port": path_analysi_protocol_parameters_destination_port,
                "icmp_code": path_analysi_protocol_parameters_icmp_code,
                "icmp_type": path_analysi_protocol_parameters_icmp_type,
                "source_port": path_analysi_protocol_parameters_source_port,
            },
            query_options={
                "is_bi_directional_analysis": path_analysi_query_options_is_bi_directional_analysis,
            },
            source_endpoint={
                "type": path_analysi_source_endpoint_type,
                "address": path_analysi_source_endpoint_address,
                "instance_id": test_instance["id"],
                "listener_id": test_listener["id"],
                "load_balancer_id": test_load_balancer["id"],
                "network_load_balancer_id": test_network_load_balancer["id"],
                "subnet_id": test_subnet["id"],
                "vlan_id": test_vlan["id"],
                "vnic_id": test_vnic_attachment["id"],
            })
        ```

        ## Import

        PathAnalysis can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:VnMonitoring/pathAnalysi:PathAnalysi test_path_analysi "id"
        ```

        :param str resource_name: The name of the resource.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] cache_control: The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        :param pulumi.Input[_builtins.str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        :param pulumi.Input[Union['PathAnalysiDestinationEndpointArgs', 'PathAnalysiDestinationEndpointArgsDict']] destination_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] path_analyzer_test_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.int] protocol: The IP protocol to used for the path analysis.
        :param pulumi.Input[Union['PathAnalysiProtocolParametersArgs', 'PathAnalysiProtocolParametersArgsDict']] protocol_parameters: Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        :param pulumi.Input[Union['PathAnalysiQueryOptionsArgs', 'PathAnalysiQueryOptionsArgsDict']] query_options: Defines the query options required for a `PathAnalyzerTest` resource.
        :param pulumi.Input[Union['PathAnalysiSourceEndpointArgs', 'PathAnalysiSourceEndpointArgsDict']] source_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] type: The type of the `PathAnalysis` query.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        ...
    @overload
    def __init__(__self__,
                 resource_name: str,
                 args: PathAnalysiArgs,
                 opts: Optional[pulumi.ResourceOptions] = None):
        """
        This resource provides the Path Analysi resource in Oracle Cloud Infrastructure Vn Monitoring service.

        Use this method to initiate a [Network Path Analyzer](https://docs.cloud.oracle.com/iaas/Content/Network/Concepts/path_analyzer.htm) analysis. This method returns
        an opc-work-request-id, and you can poll the status of the work request until it either fails or succeeds.

        If the work request status is successful, use [ListWorkRequestResults](https://docs.cloud.oracle.com/iaas/api/#/en/VnConfigAdvisor/latest/WorkRequestResult/ListWorkRequestResults)
        with the work request ID to ask for the successful analysis results. If the work request status is failed, use
        [ListWorkRequestErrors](https://docs.cloud.oracle.com/iaas/api/#/en/VnConfigAdvisor/latest/WorkRequestError/ListWorkRequestErrors)
        with the work request ID to ask for the analysis failure information. The information
        returned from either of these methods can be used to build a final report.

        ## Example Usage

        ```python
        import pulumi
        import pulumi_oci as oci

        test_path_analysi = oci.vnmonitoring.PathAnalysi("test_path_analysi",
            type=path_analysi_type,
            cache_control=path_analysi_cache_control,
            compartment_id=compartment_id,
            destination_endpoint={
                "type": path_analysi_destination_endpoint_type,
                "address": path_analysi_destination_endpoint_address,
                "instance_id": test_instance["id"],
                "listener_id": test_listener["id"],
                "load_balancer_id": test_load_balancer["id"],
                "network_load_balancer_id": test_network_load_balancer["id"],
                "subnet_id": test_subnet["id"],
                "vlan_id": test_vlan["id"],
                "vnic_id": test_vnic_attachment["id"],
            },
            path_analyzer_test_id=test_path_analyzer_test["id"],
            protocol=path_analysi_protocol,
            protocol_parameters={
                "type": path_analysi_protocol_parameters_type,
                "destination_port": path_analysi_protocol_parameters_destination_port,
                "icmp_code": path_analysi_protocol_parameters_icmp_code,
                "icmp_type": path_analysi_protocol_parameters_icmp_type,
                "source_port": path_analysi_protocol_parameters_source_port,
            },
            query_options={
                "is_bi_directional_analysis": path_analysi_query_options_is_bi_directional_analysis,
            },
            source_endpoint={
                "type": path_analysi_source_endpoint_type,
                "address": path_analysi_source_endpoint_address,
                "instance_id": test_instance["id"],
                "listener_id": test_listener["id"],
                "load_balancer_id": test_load_balancer["id"],
                "network_load_balancer_id": test_network_load_balancer["id"],
                "subnet_id": test_subnet["id"],
                "vlan_id": test_vlan["id"],
                "vnic_id": test_vnic_attachment["id"],
            })
        ```

        ## Import

        PathAnalysis can be imported using the `id`, e.g.

        ```sh
        $ pulumi import oci:VnMonitoring/pathAnalysi:PathAnalysi test_path_analysi "id"
        ```

        :param str resource_name: The name of the resource.
        :param PathAnalysiArgs args: The arguments to use to populate this resource's properties.
        :param pulumi.ResourceOptions opts: Options for the resource.
        """
        ...
    def __init__(__self__, resource_name: str, *args, **kwargs):
        resource_args, opts = _utilities.get_resource_args_opts(PathAnalysiArgs, pulumi.ResourceOptions, *args, **kwargs)
        if resource_args is not None:
            __self__._internal_init(resource_name, opts, **resource_args.__dict__)
        else:
            __self__._internal_init(resource_name, *args, **kwargs)

    def _internal_init(__self__,
                 resource_name: str,
                 opts: Optional[pulumi.ResourceOptions] = None,
                 cache_control: Optional[pulumi.Input[_builtins.str]] = None,
                 compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                 destination_endpoint: Optional[pulumi.Input[Union['PathAnalysiDestinationEndpointArgs', 'PathAnalysiDestinationEndpointArgsDict']]] = None,
                 path_analyzer_test_id: Optional[pulumi.Input[_builtins.str]] = None,
                 protocol: Optional[pulumi.Input[_builtins.int]] = None,
                 protocol_parameters: Optional[pulumi.Input[Union['PathAnalysiProtocolParametersArgs', 'PathAnalysiProtocolParametersArgsDict']]] = None,
                 query_options: Optional[pulumi.Input[Union['PathAnalysiQueryOptionsArgs', 'PathAnalysiQueryOptionsArgsDict']]] = None,
                 source_endpoint: Optional[pulumi.Input[Union['PathAnalysiSourceEndpointArgs', 'PathAnalysiSourceEndpointArgsDict']]] = None,
                 type: Optional[pulumi.Input[_builtins.str]] = None,
                 __props__=None):
        opts = pulumi.ResourceOptions.merge(_utilities.get_resource_opts_defaults(), opts)
        if not isinstance(opts, pulumi.ResourceOptions):
            raise TypeError('Expected resource options to be a ResourceOptions instance')
        if opts.id is None:
            if __props__ is not None:
                raise TypeError('__props__ is only valid when passed in combination with a valid opts.id to get an existing resource')
            __props__ = PathAnalysiArgs.__new__(PathAnalysiArgs)

            __props__.__dict__["cache_control"] = cache_control
            __props__.__dict__["compartment_id"] = compartment_id
            __props__.__dict__["destination_endpoint"] = destination_endpoint
            __props__.__dict__["path_analyzer_test_id"] = path_analyzer_test_id
            __props__.__dict__["protocol"] = protocol
            __props__.__dict__["protocol_parameters"] = protocol_parameters
            __props__.__dict__["query_options"] = query_options
            __props__.__dict__["source_endpoint"] = source_endpoint
            if type is None and not opts.urn:
                raise TypeError("Missing required property 'type'")
            __props__.__dict__["type"] = type
        super(PathAnalysi, __self__).__init__(
            'oci:VnMonitoring/pathAnalysi:PathAnalysi',
            resource_name,
            __props__,
            opts)

    @staticmethod
    def get(resource_name: str,
            id: pulumi.Input[str],
            opts: Optional[pulumi.ResourceOptions] = None,
            cache_control: Optional[pulumi.Input[_builtins.str]] = None,
            compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
            destination_endpoint: Optional[pulumi.Input[Union['PathAnalysiDestinationEndpointArgs', 'PathAnalysiDestinationEndpointArgsDict']]] = None,
            path_analyzer_test_id: Optional[pulumi.Input[_builtins.str]] = None,
            protocol: Optional[pulumi.Input[_builtins.int]] = None,
            protocol_parameters: Optional[pulumi.Input[Union['PathAnalysiProtocolParametersArgs', 'PathAnalysiProtocolParametersArgsDict']]] = None,
            query_options: Optional[pulumi.Input[Union['PathAnalysiQueryOptionsArgs', 'PathAnalysiQueryOptionsArgsDict']]] = None,
            source_endpoint: Optional[pulumi.Input[Union['PathAnalysiSourceEndpointArgs', 'PathAnalysiSourceEndpointArgsDict']]] = None,
            type: Optional[pulumi.Input[_builtins.str]] = None) -> 'PathAnalysi':
        """
        Get an existing PathAnalysi resource's state with the given name, id, and optional extra
        properties used to qualify the lookup.

        :param str resource_name: The unique name of the resulting resource.
        :param pulumi.Input[str] id: The unique provider ID of the resource to lookup.
        :param pulumi.ResourceOptions opts: Options for the resource.
        :param pulumi.Input[_builtins.str] cache_control: The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        :param pulumi.Input[_builtins.str] compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        :param pulumi.Input[Union['PathAnalysiDestinationEndpointArgs', 'PathAnalysiDestinationEndpointArgsDict']] destination_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] path_analyzer_test_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.int] protocol: The IP protocol to used for the path analysis.
        :param pulumi.Input[Union['PathAnalysiProtocolParametersArgs', 'PathAnalysiProtocolParametersArgsDict']] protocol_parameters: Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        :param pulumi.Input[Union['PathAnalysiQueryOptionsArgs', 'PathAnalysiQueryOptionsArgsDict']] query_options: Defines the query options required for a `PathAnalyzerTest` resource.
        :param pulumi.Input[Union['PathAnalysiSourceEndpointArgs', 'PathAnalysiSourceEndpointArgsDict']] source_endpoint: Information describing a source or destination in a `PathAnalyzerTest` resource.
        :param pulumi.Input[_builtins.str] type: The type of the `PathAnalysis` query.
               
               
               ** IMPORTANT **
               Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        opts = pulumi.ResourceOptions.merge(opts, pulumi.ResourceOptions(id=id))

        __props__ = _PathAnalysiState.__new__(_PathAnalysiState)

        __props__.__dict__["cache_control"] = cache_control
        __props__.__dict__["compartment_id"] = compartment_id
        __props__.__dict__["destination_endpoint"] = destination_endpoint
        __props__.__dict__["path_analyzer_test_id"] = path_analyzer_test_id
        __props__.__dict__["protocol"] = protocol
        __props__.__dict__["protocol_parameters"] = protocol_parameters
        __props__.__dict__["query_options"] = query_options
        __props__.__dict__["source_endpoint"] = source_endpoint
        __props__.__dict__["type"] = type
        return PathAnalysi(resource_name, opts=opts, __props__=__props__)

    @_builtins.property
    @pulumi.getter(name="cacheControl")
    def cache_control(self) -> pulumi.Output[_builtins.str]:
        """
        The Cache-Control HTTP header holds directives (instructions) for caching in both requests and responses.
        """
        return pulumi.get(self, "cache_control")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) for the compartment.
        """
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="destinationEndpoint")
    def destination_endpoint(self) -> pulumi.Output['outputs.PathAnalysiDestinationEndpoint']:
        """
        Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "destination_endpoint")

    @_builtins.property
    @pulumi.getter(name="pathAnalyzerTestId")
    def path_analyzer_test_id(self) -> pulumi.Output[_builtins.str]:
        """
        The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "path_analyzer_test_id")

    @_builtins.property
    @pulumi.getter
    def protocol(self) -> pulumi.Output[_builtins.int]:
        """
        The IP protocol to used for the path analysis.
        """
        return pulumi.get(self, "protocol")

    @_builtins.property
    @pulumi.getter(name="protocolParameters")
    def protocol_parameters(self) -> pulumi.Output['outputs.PathAnalysiProtocolParameters']:
        """
        Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "protocol_parameters")

    @_builtins.property
    @pulumi.getter(name="queryOptions")
    def query_options(self) -> pulumi.Output['outputs.PathAnalysiQueryOptions']:
        """
        Defines the query options required for a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "query_options")

    @_builtins.property
    @pulumi.getter(name="sourceEndpoint")
    def source_endpoint(self) -> pulumi.Output['outputs.PathAnalysiSourceEndpoint']:
        """
        Information describing a source or destination in a `PathAnalyzerTest` resource.
        """
        return pulumi.get(self, "source_endpoint")

    @_builtins.property
    @pulumi.getter
    def type(self) -> pulumi.Output[_builtins.str]:
        """
        The type of the `PathAnalysis` query.


        ** IMPORTANT **
        Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
        """
        return pulumi.get(self, "type")

