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
    'GetDomainsSecurityQuestionSettingResult',
    'AwaitableGetDomainsSecurityQuestionSettingResult',
    'get_domains_security_question_setting',
    'get_domains_security_question_setting_output',
]

@pulumi.output_type
class GetDomainsSecurityQuestionSettingResult:
    """
    A collection of values returned by getDomainsSecurityQuestionSetting.
    """
    def __init__(__self__, attribute_sets=None, attributes=None, authorization=None, compartment_ocid=None, delete_in_progress=None, domain_ocid=None, external_id=None, id=None, idcs_created_bies=None, idcs_endpoint=None, idcs_last_modified_bies=None, idcs_last_upgraded_in_release=None, idcs_prevented_operations=None, max_field_length=None, metas=None, min_answer_length=None, num_questions_to_ans=None, num_questions_to_setup=None, ocid=None, resource_type_schema_version=None, schemas=None, security_question_setting_id=None, tags=None, tenancy_ocid=None):
        if attribute_sets and not isinstance(attribute_sets, list):
            raise TypeError("Expected argument 'attribute_sets' to be a list")
        pulumi.set(__self__, "attribute_sets", attribute_sets)
        if attributes and not isinstance(attributes, str):
            raise TypeError("Expected argument 'attributes' to be a str")
        pulumi.set(__self__, "attributes", attributes)
        if authorization and not isinstance(authorization, str):
            raise TypeError("Expected argument 'authorization' to be a str")
        pulumi.set(__self__, "authorization", authorization)
        if compartment_ocid and not isinstance(compartment_ocid, str):
            raise TypeError("Expected argument 'compartment_ocid' to be a str")
        pulumi.set(__self__, "compartment_ocid", compartment_ocid)
        if delete_in_progress and not isinstance(delete_in_progress, bool):
            raise TypeError("Expected argument 'delete_in_progress' to be a bool")
        pulumi.set(__self__, "delete_in_progress", delete_in_progress)
        if domain_ocid and not isinstance(domain_ocid, str):
            raise TypeError("Expected argument 'domain_ocid' to be a str")
        pulumi.set(__self__, "domain_ocid", domain_ocid)
        if external_id and not isinstance(external_id, str):
            raise TypeError("Expected argument 'external_id' to be a str")
        pulumi.set(__self__, "external_id", external_id)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if idcs_created_bies and not isinstance(idcs_created_bies, list):
            raise TypeError("Expected argument 'idcs_created_bies' to be a list")
        pulumi.set(__self__, "idcs_created_bies", idcs_created_bies)
        if idcs_endpoint and not isinstance(idcs_endpoint, str):
            raise TypeError("Expected argument 'idcs_endpoint' to be a str")
        pulumi.set(__self__, "idcs_endpoint", idcs_endpoint)
        if idcs_last_modified_bies and not isinstance(idcs_last_modified_bies, list):
            raise TypeError("Expected argument 'idcs_last_modified_bies' to be a list")
        pulumi.set(__self__, "idcs_last_modified_bies", idcs_last_modified_bies)
        if idcs_last_upgraded_in_release and not isinstance(idcs_last_upgraded_in_release, str):
            raise TypeError("Expected argument 'idcs_last_upgraded_in_release' to be a str")
        pulumi.set(__self__, "idcs_last_upgraded_in_release", idcs_last_upgraded_in_release)
        if idcs_prevented_operations and not isinstance(idcs_prevented_operations, list):
            raise TypeError("Expected argument 'idcs_prevented_operations' to be a list")
        pulumi.set(__self__, "idcs_prevented_operations", idcs_prevented_operations)
        if max_field_length and not isinstance(max_field_length, int):
            raise TypeError("Expected argument 'max_field_length' to be a int")
        pulumi.set(__self__, "max_field_length", max_field_length)
        if metas and not isinstance(metas, list):
            raise TypeError("Expected argument 'metas' to be a list")
        pulumi.set(__self__, "metas", metas)
        if min_answer_length and not isinstance(min_answer_length, int):
            raise TypeError("Expected argument 'min_answer_length' to be a int")
        pulumi.set(__self__, "min_answer_length", min_answer_length)
        if num_questions_to_ans and not isinstance(num_questions_to_ans, int):
            raise TypeError("Expected argument 'num_questions_to_ans' to be a int")
        pulumi.set(__self__, "num_questions_to_ans", num_questions_to_ans)
        if num_questions_to_setup and not isinstance(num_questions_to_setup, int):
            raise TypeError("Expected argument 'num_questions_to_setup' to be a int")
        pulumi.set(__self__, "num_questions_to_setup", num_questions_to_setup)
        if ocid and not isinstance(ocid, str):
            raise TypeError("Expected argument 'ocid' to be a str")
        pulumi.set(__self__, "ocid", ocid)
        if resource_type_schema_version and not isinstance(resource_type_schema_version, str):
            raise TypeError("Expected argument 'resource_type_schema_version' to be a str")
        pulumi.set(__self__, "resource_type_schema_version", resource_type_schema_version)
        if schemas and not isinstance(schemas, list):
            raise TypeError("Expected argument 'schemas' to be a list")
        pulumi.set(__self__, "schemas", schemas)
        if security_question_setting_id and not isinstance(security_question_setting_id, str):
            raise TypeError("Expected argument 'security_question_setting_id' to be a str")
        pulumi.set(__self__, "security_question_setting_id", security_question_setting_id)
        if tags and not isinstance(tags, list):
            raise TypeError("Expected argument 'tags' to be a list")
        pulumi.set(__self__, "tags", tags)
        if tenancy_ocid and not isinstance(tenancy_ocid, str):
            raise TypeError("Expected argument 'tenancy_ocid' to be a str")
        pulumi.set(__self__, "tenancy_ocid", tenancy_ocid)

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
    @pulumi.getter(name="compartmentOcid")
    def compartment_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Compartment Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "compartment_ocid")

    @_builtins.property
    @pulumi.getter(name="deleteInProgress")
    def delete_in_progress(self) -> _builtins.bool:
        """
        A boolean flag indicating this resource in the process of being deleted. Usually set to true when synchronous deletion of the resource would take too long.
        """
        return pulumi.get(self, "delete_in_progress")

    @_builtins.property
    @pulumi.getter(name="domainOcid")
    def domain_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Domain Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "domain_ocid")

    @_builtins.property
    @pulumi.getter(name="externalId")
    def external_id(self) -> _builtins.str:
        """
        An identifier for the Resource as defined by the Service Consumer. The externalId may simplify identification of the Resource between Service Consumer and Service Provider by allowing the Consumer to refer to the Resource with its own identifier, obviating the need to store a local mapping between the local identifier of the Resource and the identifier used by the Service Provider. Each Resource MAY include a non-empty externalId value. The value of the externalId attribute is always issued by the Service Consumer and can never be specified by the Service Provider. The Service Provider MUST always interpret the externalId as scoped to the Service Consumer's tenant.
        """
        return pulumi.get(self, "external_id")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        Unique identifier for the SCIM Resource as defined by the Service Provider. Each representation of the Resource MUST include a non-empty id value. This identifier MUST be unique across the Service Provider's entire set of Resources. It MUST be a stable, non-reassignable identifier that does not change when the same Resource is returned in subsequent requests. The value of the id attribute is always issued by the Service Provider and MUST never be specified by the Service Consumer. bulkId: is a reserved keyword and MUST NOT be used in the unique identifier.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="idcsCreatedBies")
    def idcs_created_bies(self) -> Sequence['outputs.GetDomainsSecurityQuestionSettingIdcsCreatedByResult']:
        """
        The User or App who created the Resource
        """
        return pulumi.get(self, "idcs_created_bies")

    @_builtins.property
    @pulumi.getter(name="idcsEndpoint")
    def idcs_endpoint(self) -> _builtins.str:
        return pulumi.get(self, "idcs_endpoint")

    @_builtins.property
    @pulumi.getter(name="idcsLastModifiedBies")
    def idcs_last_modified_bies(self) -> Sequence['outputs.GetDomainsSecurityQuestionSettingIdcsLastModifiedByResult']:
        """
        The User or App who modified the Resource
        """
        return pulumi.get(self, "idcs_last_modified_bies")

    @_builtins.property
    @pulumi.getter(name="idcsLastUpgradedInRelease")
    def idcs_last_upgraded_in_release(self) -> _builtins.str:
        """
        The release number when the resource was upgraded.
        """
        return pulumi.get(self, "idcs_last_upgraded_in_release")

    @_builtins.property
    @pulumi.getter(name="idcsPreventedOperations")
    def idcs_prevented_operations(self) -> Sequence[_builtins.str]:
        """
        Each value of this attribute specifies an operation that only an internal client may perform on this particular resource.
        """
        return pulumi.get(self, "idcs_prevented_operations")

    @_builtins.property
    @pulumi.getter(name="maxFieldLength")
    def max_field_length(self) -> _builtins.int:
        """
        Indicates the maximum length of following fields Security Questions, Answer and Hint
        """
        return pulumi.get(self, "max_field_length")

    @_builtins.property
    @pulumi.getter
    def metas(self) -> Sequence['outputs.GetDomainsSecurityQuestionSettingMetaResult']:
        """
        A complex attribute that contains resource metadata. All sub-attributes are OPTIONAL.
        """
        return pulumi.get(self, "metas")

    @_builtins.property
    @pulumi.getter(name="minAnswerLength")
    def min_answer_length(self) -> _builtins.int:
        """
        Indicates the minimum length of answer for security questions
        """
        return pulumi.get(self, "min_answer_length")

    @_builtins.property
    @pulumi.getter(name="numQuestionsToAns")
    def num_questions_to_ans(self) -> _builtins.int:
        """
        Indicates the number of security questions that a user must answer
        """
        return pulumi.get(self, "num_questions_to_ans")

    @_builtins.property
    @pulumi.getter(name="numQuestionsToSetup")
    def num_questions_to_setup(self) -> _builtins.int:
        """
        Indicates the number of security questions a user must setup
        """
        return pulumi.get(self, "num_questions_to_setup")

    @_builtins.property
    @pulumi.getter
    def ocid(self) -> _builtins.str:
        """
        Unique Oracle Cloud Infrastructure identifier for the SCIM Resource.
        """
        return pulumi.get(self, "ocid")

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
    @pulumi.getter(name="securityQuestionSettingId")
    def security_question_setting_id(self) -> _builtins.str:
        return pulumi.get(self, "security_question_setting_id")

    @_builtins.property
    @pulumi.getter
    def tags(self) -> Sequence['outputs.GetDomainsSecurityQuestionSettingTagResult']:
        """
        A list of tags on this resource.
        """
        return pulumi.get(self, "tags")

    @_builtins.property
    @pulumi.getter(name="tenancyOcid")
    def tenancy_ocid(self) -> _builtins.str:
        """
        Oracle Cloud Infrastructure Tenant Id (ocid) in which the resource lives.
        """
        return pulumi.get(self, "tenancy_ocid")


class AwaitableGetDomainsSecurityQuestionSettingResult(GetDomainsSecurityQuestionSettingResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetDomainsSecurityQuestionSettingResult(
            attribute_sets=self.attribute_sets,
            attributes=self.attributes,
            authorization=self.authorization,
            compartment_ocid=self.compartment_ocid,
            delete_in_progress=self.delete_in_progress,
            domain_ocid=self.domain_ocid,
            external_id=self.external_id,
            id=self.id,
            idcs_created_bies=self.idcs_created_bies,
            idcs_endpoint=self.idcs_endpoint,
            idcs_last_modified_bies=self.idcs_last_modified_bies,
            idcs_last_upgraded_in_release=self.idcs_last_upgraded_in_release,
            idcs_prevented_operations=self.idcs_prevented_operations,
            max_field_length=self.max_field_length,
            metas=self.metas,
            min_answer_length=self.min_answer_length,
            num_questions_to_ans=self.num_questions_to_ans,
            num_questions_to_setup=self.num_questions_to_setup,
            ocid=self.ocid,
            resource_type_schema_version=self.resource_type_schema_version,
            schemas=self.schemas,
            security_question_setting_id=self.security_question_setting_id,
            tags=self.tags,
            tenancy_ocid=self.tenancy_ocid)


def get_domains_security_question_setting(attribute_sets: Optional[Sequence[_builtins.str]] = None,
                                          attributes: Optional[_builtins.str] = None,
                                          authorization: Optional[_builtins.str] = None,
                                          idcs_endpoint: Optional[_builtins.str] = None,
                                          resource_type_schema_version: Optional[_builtins.str] = None,
                                          security_question_setting_id: Optional[_builtins.str] = None,
                                          opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetDomainsSecurityQuestionSettingResult:
    """
    This data source provides details about a specific Security Question Setting resource in Oracle Cloud Infrastructure Identity Domains service.

    Get a security question setting.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_question_setting = oci.Identity.get_domains_security_question_setting(idcs_endpoint=test_domain["url"],
        security_question_setting_id=test_security_question_setting_oci_identity_domains_security_question_setting["id"],
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
    :param _builtins.str security_question_setting_id: ID of the resource
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    __args__['securityQuestionSettingId'] = security_question_setting_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Identity/getDomainsSecurityQuestionSetting:getDomainsSecurityQuestionSetting', __args__, opts=opts, typ=GetDomainsSecurityQuestionSettingResult).value

    return AwaitableGetDomainsSecurityQuestionSettingResult(
        attribute_sets=pulumi.get(__ret__, 'attribute_sets'),
        attributes=pulumi.get(__ret__, 'attributes'),
        authorization=pulumi.get(__ret__, 'authorization'),
        compartment_ocid=pulumi.get(__ret__, 'compartment_ocid'),
        delete_in_progress=pulumi.get(__ret__, 'delete_in_progress'),
        domain_ocid=pulumi.get(__ret__, 'domain_ocid'),
        external_id=pulumi.get(__ret__, 'external_id'),
        id=pulumi.get(__ret__, 'id'),
        idcs_created_bies=pulumi.get(__ret__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__ret__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__ret__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__ret__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__ret__, 'idcs_prevented_operations'),
        max_field_length=pulumi.get(__ret__, 'max_field_length'),
        metas=pulumi.get(__ret__, 'metas'),
        min_answer_length=pulumi.get(__ret__, 'min_answer_length'),
        num_questions_to_ans=pulumi.get(__ret__, 'num_questions_to_ans'),
        num_questions_to_setup=pulumi.get(__ret__, 'num_questions_to_setup'),
        ocid=pulumi.get(__ret__, 'ocid'),
        resource_type_schema_version=pulumi.get(__ret__, 'resource_type_schema_version'),
        schemas=pulumi.get(__ret__, 'schemas'),
        security_question_setting_id=pulumi.get(__ret__, 'security_question_setting_id'),
        tags=pulumi.get(__ret__, 'tags'),
        tenancy_ocid=pulumi.get(__ret__, 'tenancy_ocid'))
def get_domains_security_question_setting_output(attribute_sets: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                                 attributes: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                 authorization: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                 idcs_endpoint: Optional[pulumi.Input[_builtins.str]] = None,
                                                 resource_type_schema_version: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                 security_question_setting_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                 opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetDomainsSecurityQuestionSettingResult]:
    """
    This data source provides details about a specific Security Question Setting resource in Oracle Cloud Infrastructure Identity Domains service.

    Get a security question setting.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_security_question_setting = oci.Identity.get_domains_security_question_setting(idcs_endpoint=test_domain["url"],
        security_question_setting_id=test_security_question_setting_oci_identity_domains_security_question_setting["id"],
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
    :param _builtins.str security_question_setting_id: ID of the resource
    """
    __args__ = dict()
    __args__['attributeSets'] = attribute_sets
    __args__['attributes'] = attributes
    __args__['authorization'] = authorization
    __args__['idcsEndpoint'] = idcs_endpoint
    __args__['resourceTypeSchemaVersion'] = resource_type_schema_version
    __args__['securityQuestionSettingId'] = security_question_setting_id
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Identity/getDomainsSecurityQuestionSetting:getDomainsSecurityQuestionSetting', __args__, opts=opts, typ=GetDomainsSecurityQuestionSettingResult)
    return __ret__.apply(lambda __response__: GetDomainsSecurityQuestionSettingResult(
        attribute_sets=pulumi.get(__response__, 'attribute_sets'),
        attributes=pulumi.get(__response__, 'attributes'),
        authorization=pulumi.get(__response__, 'authorization'),
        compartment_ocid=pulumi.get(__response__, 'compartment_ocid'),
        delete_in_progress=pulumi.get(__response__, 'delete_in_progress'),
        domain_ocid=pulumi.get(__response__, 'domain_ocid'),
        external_id=pulumi.get(__response__, 'external_id'),
        id=pulumi.get(__response__, 'id'),
        idcs_created_bies=pulumi.get(__response__, 'idcs_created_bies'),
        idcs_endpoint=pulumi.get(__response__, 'idcs_endpoint'),
        idcs_last_modified_bies=pulumi.get(__response__, 'idcs_last_modified_bies'),
        idcs_last_upgraded_in_release=pulumi.get(__response__, 'idcs_last_upgraded_in_release'),
        idcs_prevented_operations=pulumi.get(__response__, 'idcs_prevented_operations'),
        max_field_length=pulumi.get(__response__, 'max_field_length'),
        metas=pulumi.get(__response__, 'metas'),
        min_answer_length=pulumi.get(__response__, 'min_answer_length'),
        num_questions_to_ans=pulumi.get(__response__, 'num_questions_to_ans'),
        num_questions_to_setup=pulumi.get(__response__, 'num_questions_to_setup'),
        ocid=pulumi.get(__response__, 'ocid'),
        resource_type_schema_version=pulumi.get(__response__, 'resource_type_schema_version'),
        schemas=pulumi.get(__response__, 'schemas'),
        security_question_setting_id=pulumi.get(__response__, 'security_question_setting_id'),
        tags=pulumi.get(__response__, 'tags'),
        tenancy_ocid=pulumi.get(__response__, 'tenancy_ocid')))
