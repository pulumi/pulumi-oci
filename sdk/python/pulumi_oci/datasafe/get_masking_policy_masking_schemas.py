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

__all__ = [
    'GetMaskingPolicyMaskingSchemasResult',
    'AwaitableGetMaskingPolicyMaskingSchemasResult',
    'get_masking_policy_masking_schemas',
    'get_masking_policy_masking_schemas_output',
]

@pulumi.output_type
class GetMaskingPolicyMaskingSchemasResult:
    """
    A collection of values returned by getMaskingPolicyMaskingSchemas.
    """
    def __init__(__self__, filters=None, id=None, masking_policy_id=None, masking_schema_collections=None, schema_names=None):
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if masking_policy_id and not isinstance(masking_policy_id, str):
            raise TypeError("Expected argument 'masking_policy_id' to be a str")
        pulumi.set(__self__, "masking_policy_id", masking_policy_id)
        if masking_schema_collections and not isinstance(masking_schema_collections, list):
            raise TypeError("Expected argument 'masking_schema_collections' to be a list")
        pulumi.set(__self__, "masking_schema_collections", masking_schema_collections)
        if schema_names and not isinstance(schema_names, list):
            raise TypeError("Expected argument 'schema_names' to be a list")
        pulumi.set(__self__, "schema_names", schema_names)

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetMaskingPolicyMaskingSchemasFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="maskingPolicyId")
    def masking_policy_id(self) -> _builtins.str:
        return pulumi.get(self, "masking_policy_id")

    @_builtins.property
    @pulumi.getter(name="maskingSchemaCollections")
    def masking_schema_collections(self) -> Sequence['outputs.GetMaskingPolicyMaskingSchemasMaskingSchemaCollectionResult']:
        """
        The list of masking_schema_collection.
        """
        return pulumi.get(self, "masking_schema_collections")

    @_builtins.property
    @pulumi.getter(name="schemaNames")
    def schema_names(self) -> Optional[Sequence[_builtins.str]]:
        """
        The database schema that contains the masking column.
        """
        return pulumi.get(self, "schema_names")


class AwaitableGetMaskingPolicyMaskingSchemasResult(GetMaskingPolicyMaskingSchemasResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMaskingPolicyMaskingSchemasResult(
            filters=self.filters,
            id=self.id,
            masking_policy_id=self.masking_policy_id,
            masking_schema_collections=self.masking_schema_collections,
            schema_names=self.schema_names)


def get_masking_policy_masking_schemas(filters: Optional[Sequence[Union['GetMaskingPolicyMaskingSchemasFilterArgs', 'GetMaskingPolicyMaskingSchemasFilterArgsDict']]] = None,
                                       masking_policy_id: Optional[_builtins.str] = None,
                                       schema_names: Optional[Sequence[_builtins.str]] = None,
                                       opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMaskingPolicyMaskingSchemasResult:
    """
    This data source provides the list of Masking Policy Masking Schemas in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of masking schemas present in the specified masking policy and based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_policy_masking_schemas = oci.DataSafe.get_masking_policy_masking_schemas(masking_policy_id=test_masking_policy["id"],
        schema_names=masking_policy_masking_schema_schema_name)
    ```


    :param _builtins.str masking_policy_id: The OCID of the masking policy.
    :param Sequence[_builtins.str] schema_names: A filter to return only items related to specific schema name.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['maskingPolicyId'] = masking_policy_id
    __args__['schemaNames'] = schema_names
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:DataSafe/getMaskingPolicyMaskingSchemas:getMaskingPolicyMaskingSchemas', __args__, opts=opts, typ=GetMaskingPolicyMaskingSchemasResult).value

    return AwaitableGetMaskingPolicyMaskingSchemasResult(
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        masking_policy_id=pulumi.get(__ret__, 'masking_policy_id'),
        masking_schema_collections=pulumi.get(__ret__, 'masking_schema_collections'),
        schema_names=pulumi.get(__ret__, 'schema_names'))
def get_masking_policy_masking_schemas_output(filters: Optional[pulumi.Input[Optional[Sequence[Union['GetMaskingPolicyMaskingSchemasFilterArgs', 'GetMaskingPolicyMaskingSchemasFilterArgsDict']]]]] = None,
                                              masking_policy_id: Optional[pulumi.Input[_builtins.str]] = None,
                                              schema_names: Optional[pulumi.Input[Optional[Sequence[_builtins.str]]]] = None,
                                              opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetMaskingPolicyMaskingSchemasResult]:
    """
    This data source provides the list of Masking Policy Masking Schemas in Oracle Cloud Infrastructure Data Safe service.

    Gets a list of masking schemas present in the specified masking policy and based on the specified query parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_masking_policy_masking_schemas = oci.DataSafe.get_masking_policy_masking_schemas(masking_policy_id=test_masking_policy["id"],
        schema_names=masking_policy_masking_schema_schema_name)
    ```


    :param _builtins.str masking_policy_id: The OCID of the masking policy.
    :param Sequence[_builtins.str] schema_names: A filter to return only items related to specific schema name.
    """
    __args__ = dict()
    __args__['filters'] = filters
    __args__['maskingPolicyId'] = masking_policy_id
    __args__['schemaNames'] = schema_names
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:DataSafe/getMaskingPolicyMaskingSchemas:getMaskingPolicyMaskingSchemas', __args__, opts=opts, typ=GetMaskingPolicyMaskingSchemasResult)
    return __ret__.apply(lambda __response__: GetMaskingPolicyMaskingSchemasResult(
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        masking_policy_id=pulumi.get(__response__, 'masking_policy_id'),
        masking_schema_collections=pulumi.get(__response__, 'masking_schema_collections'),
        schema_names=pulumi.get(__response__, 'schema_names')))
