# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities

__all__ = [
    'GetLogSavedSearchResult',
    'AwaitableGetLogSavedSearchResult',
    'get_log_saved_search',
    'get_log_saved_search_output',
]

@pulumi.output_type
class GetLogSavedSearchResult:
    """
    A collection of values returned by getLogSavedSearch.
    """
    def __init__(__self__, compartment_id=None, defined_tags=None, description=None, freeform_tags=None, id=None, log_saved_search_id=None, name=None, query=None, state=None, time_created=None, time_last_modified=None):
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if description and not isinstance(description, str):
            raise TypeError("Expected argument 'description' to be a str")
        pulumi.set(__self__, "description", description)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if log_saved_search_id and not isinstance(log_saved_search_id, str):
            raise TypeError("Expected argument 'log_saved_search_id' to be a str")
        pulumi.set(__self__, "log_saved_search_id", log_saved_search_id)
        if name and not isinstance(name, str):
            raise TypeError("Expected argument 'name' to be a str")
        pulumi.set(__self__, "name", name)
        if query and not isinstance(query, str):
            raise TypeError("Expected argument 'query' to be a str")
        pulumi.set(__self__, "query", query)
        if state and not isinstance(state, str):
            raise TypeError("Expected argument 'state' to be a str")
        pulumi.set(__self__, "state", state)
        if time_created and not isinstance(time_created, str):
            raise TypeError("Expected argument 'time_created' to be a str")
        pulumi.set(__self__, "time_created", time_created)
        if time_last_modified and not isinstance(time_last_modified, str):
            raise TypeError("Expected argument 'time_last_modified' to be a str")
        pulumi.set(__self__, "time_last_modified", time_last_modified)

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The OCID of the compartment that the resource belongs to.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter
    def description(self) -> str:
        """
        Description for this resource.
        """
        return pulumi.get(self, "description")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        The OCID of the resource.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="logSavedSearchId")
    def log_saved_search_id(self) -> str:
        return pulumi.get(self, "log_saved_search_id")

    @property
    @pulumi.getter
    def name(self) -> str:
        """
        The user-friendly display name. This must be unique within the enclosing resource, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "name")

    @property
    @pulumi.getter
    def query(self) -> str:
        """
        The search query that is saved.
        """
        return pulumi.get(self, "query")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The state of the LogSavedSearch
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        Time the resource was created.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeLastModified")
    def time_last_modified(self) -> str:
        """
        Time the resource was last modified.
        """
        return pulumi.get(self, "time_last_modified")


class AwaitableGetLogSavedSearchResult(GetLogSavedSearchResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetLogSavedSearchResult(
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            description=self.description,
            freeform_tags=self.freeform_tags,
            id=self.id,
            log_saved_search_id=self.log_saved_search_id,
            name=self.name,
            query=self.query,
            state=self.state,
            time_created=self.time_created,
            time_last_modified=self.time_last_modified)


def get_log_saved_search(log_saved_search_id: Optional[str] = None,
                         opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetLogSavedSearchResult:
    """
    This data source provides details about a specific Log Saved Search resource in Oracle Cloud Infrastructure Logging service.

    Retrieves a log saved search.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_log_saved_search = oci.Logging.get_log_saved_search(log_saved_search_id=oci_logging_log_saved_search["test_log_saved_search"]["id"])
    ```


    :param str log_saved_search_id: OCID of the logSavedSearch
    """
    __args__ = dict()
    __args__['logSavedSearchId'] = log_saved_search_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Logging/getLogSavedSearch:getLogSavedSearch', __args__, opts=opts, typ=GetLogSavedSearchResult).value

    return AwaitableGetLogSavedSearchResult(
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        description=__ret__.description,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        log_saved_search_id=__ret__.log_saved_search_id,
        name=__ret__.name,
        query=__ret__.query,
        state=__ret__.state,
        time_created=__ret__.time_created,
        time_last_modified=__ret__.time_last_modified)


@_utilities.lift_output_func(get_log_saved_search)
def get_log_saved_search_output(log_saved_search_id: Optional[pulumi.Input[str]] = None,
                                opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetLogSavedSearchResult]:
    """
    This data source provides details about a specific Log Saved Search resource in Oracle Cloud Infrastructure Logging service.

    Retrieves a log saved search.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_log_saved_search = oci.Logging.get_log_saved_search(log_saved_search_id=oci_logging_log_saved_search["test_log_saved_search"]["id"])
    ```


    :param str log_saved_search_id: OCID of the logSavedSearch
    """
    ...