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
    'GetDomainsSecurityQuestionSettingsResult',
    'AwaitableGetDomainsSecurityQuestionSettingsResult',
    'get_domains_security_question_settings',
    'get_domains_security_question_settings_output',
]

@pulumi.output_type
class GetDomainsSecurityQuestionSettingsResult:
    """
    A collection of values returned by getDomainsSecurityQuestionSettings.
    """
    def __init__(__self__, attribute_sets=None, attributes=None, authorization=None, compartment_id=None, id=None, idcs_endpoint=None, items_per_page=None, resource_type_schema_version=None, schemas=None, security_question_settings=None, start_index=None, total_results=None):
        if attribute_sets and not isinstance(attribute_sets, list):
            raise TypeError("Expected argument 'attribute_sets' to be a list")
        pulumi.set(__self__, "attribute_sets", attribute_sets)
        if attributes and not isinstance(attributes, str):
            raise TypeError("Expected argument 'attributes' to be a str")
        pulumi.set(__self__, "attributes", attributes)
        if authorization and not isinstance(authorization, str):
            raise TypeError("Expected argument 'authorization' to be a str")
        pulumi.set(__self__, "authorization", authorization)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if idcs_endpoint and not isinstance(idcs_endpoint, str):
            raise TypeError("Expected argument 'idcs_endpoint' to be a str")
        pulumi.set(__self__, "idcs_endpoint", idcs_endpoint)
        if items_per_page and not isinstance(items_per_page, int):
            raise TypeError("Expected argument 'items_per_page' to be a int")
        pulumi.set(__self__, "items_per_page", items_per_page)
        if resource_type_schema_version and not isinstance(resource_type_schema_version, str):
            raise TypeError("Expected argument 'resource_type_schema_version' to be a str")
        pulumi.set(__self__, "resource_type_schema_version", resource_type_schema_version)
        if schemas and not isinstance(schemas, list):
            raise TypeError("Expected argument 'schemas' to be a list")
        pulumi.set(__self__, "schemas", schemas)
        if security_question_settings and not isinstance(security_question_settings, list):
            raise TypeError("Expected argument 'security_question_settings' to be a list")
        pulumi.set(__self__, "security_question_settings", security_question_settings)
        if start_index and not isinstance(start_index, int):
            raise TypeError("Expected argument 'start_index' to be a int")
        pulumi.set(__self__, "start_index", start_index)
        if total_results and not isinstance(total_results, int):
            raise TypeError("Expected argument 'total_results' to be a int")
        pulumi.set(__self__, "total_results", total_results)

    @_builtins.property
    @pulumi.getter(name="attributeSets")
    def attribute_sets(self) -> Optional[Sequence[_builtins.str]]:
        return pulumi.get(self, "attribute_sets")

    @_builtins.property
    @pulumi.getter
    def attributes(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "attributes")

    @_builtins.property
    @pulumi.getter
    def authorization(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "authorization")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="idcsEndpoint")
    def idcs_endpoint(self) -> _builtins.str:
        return pulumi.get(self, "idcs_endpoint")

    @_builtins.property
    @pulumi.getter(name="itemsPerPage")
    def items_per_page(self) -> _builtins.int:
        return pulumi.get(self, "items_per_page")

    @_builtins.property
    @pulumi.getter(name="resourceTypeSchemaVersion")
    def resource_type_schema_version(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "resource_type_schema_version")

    @_builtins.property
    @pulumi.getter
    def schemas(self) -> Sequence[_builtins.str]:
        """
        REQUIRED. The schemas attribute is an array of Strings which allows introspection of the supported schema version for a SCIM representation as well any schema extensions supported by that representation. Each String value must be a unique URI. This specification defines URIs for User, Group, and a standard \\"enterprise\\" extension. All representations of SCIM schema MUST include a non-zero value array with value(s) of the URIs supported by that representation. Duplicate values MUST NOT be included. Value order is not specified and MUST not impact behavior.
        """
        return pulumi.get(self, "schemas")

    @_builtins.property
    @pulumi.getter(name="securityQuestionSettings")
    def security_question_settings(self) -> Sequence['outputs.GetDomainsSecurityQuestionSettingsSecurityQuestionSettingResult']:
        """
        The list of security_question_settings.
        """
        return pulumi.get(self, "security_question_settings")

    @_builtins.property
    @pulumi.getter(name="startIndex")
    def start_index(self) -> _builtins.int:
        return pulumi.get(self, "start_index")

    @_builtins.property
    @pulumi.getter(name="totalResults")
    def total_results(self) -> _builtins.int:
        return pulumi.get(self, "total_results")


class AwaitableGetDomainsSecurityQuestionSettingsResult(GetDomainsSecurityQuestionSettingsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDomainsSecurityQuestionSettingsResult(
            attribute_sets=self.attribute_sets,
            attributes=self.attributes,
            authorization=self.authorization,
            compartment_id=self.compartment_id,
            id=self.id,
            idcs_endpoint=self.idcs_endpoint,
            items_per_page=self.items_per_page,
            resource_type_schema_version=self.resource_type_schema_version,
            schemas=self.schemas,
            security_question_settings=self.security_question_settings,
            start_index=self.start_index,
            total_results=self.total_results)


def get_domains_security_question_settings(attribute_sets: Optional[Sequence[_builtins.str]] = None,
                                           attributes: Optional[_builtins.str] = None,
                                           authorization: Optional[_builtins.str] = None,
                                           compartment_id: Optional[_builtins.str] = None,
                                           idcs_endpoint: Optional[_builtins.str] = None,
                                           resource_type_schema_version: Optional[_builtins.str] = None,
                                           opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDomainsSecurityQuestionSettingsResult:
    """
    This data source provides the list of Security Question Settings in Oracle Cloud Infrastructure Identity Domains service.

    Search for security question settings.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_question_settings = oci.Identity.get_domains_security_question_settings(idcs_endpoint=test_domain["url"],
        attribute_sets=["all"],
        attributes="",
        authorization=security_question_setting_authorization,
        resource_type_schema_version=security_question_setting_resource_type_schema_version)
    ```


    :param Sequence[_builtins.str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param _builtins.str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param _builtins.str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param _builtins.str idcs_endpoint: The basic endpoint for the identity domain
    :param _builtins.str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['compartmentId'] = compartment_id
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getDomainsSecurityQuestionSettings:getDomainsSecurityQuestionSettings', __args__, opts=opts, typ=GetDomainsSecurityQuestionSettingsResult).value

    return AwaitableGetDomainsSecurityQuestionSettingsResult(
        attribute_sets=pulumi.get(__ret__, 'attribute_sets'),
        attributes=pulumi.get(__ret__, 'attributes'),
        authorization=pulumi.get(__ret__, 'authorization'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        id=pulumi.get(__ret__, 'id'),
        idcs_endpoint=pulumi.get(__ret__, 'idcs_endpoint'),
        items_per_page=pulumi.get(__ret__, 'items_per_page'),
        resource_type_schema_version=pulumi.get(__ret__, 'resource_type_schema_version'),
        schemas=pulumi.get(__ret__, 'schemas'),
        security_question_settings=pulumi.get(__ret__, 'security_question_settings'),
        start_index=pulumi.get(__ret__, 'start_index'),
        total_results=pulumi.get(__ret__, 'total_results'))
def get_domains_security_question_settings_output(attribute_sets: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                  attributes: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                  authorization: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                  compartment_id: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                  idcs_endpoint: Optional[pulumi.Input[_builtins.str]] = None,
                                                  resource_type_schema_version: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                  opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDomainsSecurityQuestionSettingsResult]:
    """
    This data source provides the list of Security Question Settings in Oracle Cloud Infrastructure Identity Domains service.

    Search for security question settings.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_question_settings = oci.Identity.get_domains_security_question_settings(idcs_endpoint=test_domain["url"],
        attribute_sets=["all"],
        attributes="",
        authorization=security_question_setting_authorization,
        resource_type_schema_version=security_question_setting_resource_type_schema_version)
    ```


    :param Sequence[_builtins.str] attribute_sets: A multi-valued list of strings indicating the return type of attribute definition. The specified set of attributes can be fetched by the return type of the attribute. One or more values can be given together to fetch more than one group of attributes. If 'attributes' query parameter is also available, union of the two is fetched. Valid values - all, always, never, request, default. Values are case-insensitive.
    :param _builtins.str attributes: A comma-delimited string that specifies the names of resource attributes that should be returned in the response. By default, a response that contains resource attributes contains only attributes that are defined in the schema for that resource type as returned=always or returned=default. An attribute that is defined as returned=request is returned in a response only if the request specifies its name in the value of this query parameter. If a request specifies this query parameter, the response contains the attributes that this query parameter specifies, as well as any attribute that is defined as returned=always.
    :param _builtins.str authorization: The Authorization field value consists of credentials containing the authentication information of the user agent for the realm of the resource being requested.
    :param _builtins.str idcs_endpoint: The basic endpoint for the identity domain
    :param _builtins.str resource_type_schema_version: An endpoint-specific schema version number to use in the Request. Allowed version values are Earliest Version or Latest Version as specified in each REST API endpoint description, or any sequential number inbetween. All schema attributes/body parameters are a part of version 1. After version 1, any attributes added or deprecated will be tagged with the version that they were added to or deprecated in. If no version is provided, the latest schema version is returned.
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['compartmentId'] = compartment_id
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getDomainsSecurityQuestionSettings:getDomainsSecurityQuestionSettings', __args__, opts=opts, typ=GetDomainsSecurityQuestionSettingsResult)
    return __ret__.apply(lambda __response__: GetDomainsSecurityQuestionSettingsResult(
        attribute_sets=pulumi.get(__response__, 'attribute_sets'),
        attributes=pulumi.get(__response__, 'attributes'),
        authorization=pulumi.get(__response__, 'authorization'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        id=pulumi.get(__response__, 'id'),
        idcs_endpoint=pulumi.get(__response__, 'idcs_endpoint'),
        items_per_page=pulumi.get(__response__, 'items_per_page'),
        resource_type_schema_version=pulumi.get(__response__, 'resource_type_schema_version'),
        schemas=pulumi.get(__response__, 'schemas'),
        security_question_settings=pulumi.get(__response__, 'security_question_settings'),
        start_index=pulumi.get(__response__, 'start_index'),
        total_results=pulumi.get(__response__, 'total_results')))
