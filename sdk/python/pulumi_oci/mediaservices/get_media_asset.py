# coding=utf-8
# *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
# *** Do not edit by hand unless you're certain you know what you are doing! ***

import copy
import warnings
import pulumi
import pulumi.runtime
from typing import Any, Mapping, Optional, Sequence, Union, overload
from .. import _utilities
from . import outputs

__all__ = [
    'GetMediaAssetResult',
    'AwaitableGetMediaAssetResult',
    'get_media_asset',
    'get_media_asset_output',
]

@pulumi.output_type
class GetMediaAssetResult:
    """
    A collection of values returned by getMediaAsset.
    """
    def __init__(__self__, bucket=None, compartment_id=None, defined_tags=None, display_name=None, freeform_tags=None, id=None, master_media_asset_id=None, media_asset_id=None, media_asset_tags=None, media_workflow_job_id=None, metadatas=None, namespace=None, object=None, object_etag=None, parent_media_asset_id=None, segment_range_end_index=None, segment_range_start_index=None, source_media_workflow_id=None, source_media_workflow_version=None, state=None, system_tags=None, time_created=None, time_updated=None, type=None):
        if bucket and not isinstance(bucket, str):
            raise TypeError("Expected argument 'bucket' to be a str")
        pulumi.set(__self__, "bucket", bucket)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if defined_tags and not isinstance(defined_tags, dict):
            raise TypeError("Expected argument 'defined_tags' to be a dict")
        pulumi.set(__self__, "defined_tags", defined_tags)
        if display_name and not isinstance(display_name, str):
            raise TypeError("Expected argument 'display_name' to be a str")
        pulumi.set(__self__, "display_name", display_name)
        if freeform_tags and not isinstance(freeform_tags, dict):
            raise TypeError("Expected argument 'freeform_tags' to be a dict")
        pulumi.set(__self__, "freeform_tags", freeform_tags)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if master_media_asset_id and not isinstance(master_media_asset_id, str):
            raise TypeError("Expected argument 'master_media_asset_id' to be a str")
        pulumi.set(__self__, "master_media_asset_id", master_media_asset_id)
        if media_asset_id and not isinstance(media_asset_id, str):
            raise TypeError("Expected argument 'media_asset_id' to be a str")
        pulumi.set(__self__, "media_asset_id", media_asset_id)
        if media_asset_tags and not isinstance(media_asset_tags, list):
            raise TypeError("Expected argument 'media_asset_tags' to be a list")
        pulumi.set(__self__, "media_asset_tags", media_asset_tags)
        if media_workflow_job_id and not isinstance(media_workflow_job_id, str):
            raise TypeError("Expected argument 'media_workflow_job_id' to be a str")
        pulumi.set(__self__, "media_workflow_job_id", media_workflow_job_id)
        if metadatas and not isinstance(metadatas, list):
            raise TypeError("Expected argument 'metadatas' to be a list")
        pulumi.set(__self__, "metadatas", metadatas)
        if namespace and not isinstance(namespace, str):
            raise TypeError("Expected argument 'namespace' to be a str")
        pulumi.set(__self__, "namespace", namespace)
        if object and not isinstance(object, str):
            raise TypeError("Expected argument 'object' to be a str")
        pulumi.set(__self__, "object", object)
        if object_etag and not isinstance(object_etag, str):
            raise TypeError("Expected argument 'object_etag' to be a str")
        pulumi.set(__self__, "object_etag", object_etag)
        if parent_media_asset_id and not isinstance(parent_media_asset_id, str):
            raise TypeError("Expected argument 'parent_media_asset_id' to be a str")
        pulumi.set(__self__, "parent_media_asset_id", parent_media_asset_id)
        if segment_range_end_index and not isinstance(segment_range_end_index, str):
            raise TypeError("Expected argument 'segment_range_end_index' to be a str")
        pulumi.set(__self__, "segment_range_end_index", segment_range_end_index)
        if segment_range_start_index and not isinstance(segment_range_start_index, str):
            raise TypeError("Expected argument 'segment_range_start_index' to be a str")
        pulumi.set(__self__, "segment_range_start_index", segment_range_start_index)
        if source_media_workflow_id and not isinstance(source_media_workflow_id, str):
            raise TypeError("Expected argument 'source_media_workflow_id' to be a str")
        pulumi.set(__self__, "source_media_workflow_id", source_media_workflow_id)
        if source_media_workflow_version and not isinstance(source_media_workflow_version, str):
            raise TypeError("Expected argument 'source_media_workflow_version' to be a str")
        pulumi.set(__self__, "source_media_workflow_version", source_media_workflow_version)
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
        if type and not isinstance(type, str):
            raise TypeError("Expected argument 'type' to be a str")
        pulumi.set(__self__, "type", type)

    @property
    @pulumi.getter
    def bucket(self) -> str:
        """
        The name of the object storage bucket where this represented asset is located.
        """
        return pulumi.get(self, "bucket")

    @property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> str:
        """
        The ID of the compartment containing the MediaAsset.
        """
        return pulumi.get(self, "compartment_id")

    @property
    @pulumi.getter(name="definedTags")
    def defined_tags(self) -> Mapping[str, Any]:
        """
        Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
        """
        return pulumi.get(self, "defined_tags")

    @property
    @pulumi.getter(name="displayName")
    def display_name(self) -> str:
        """
        A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
        """
        return pulumi.get(self, "display_name")

    @property
    @pulumi.getter(name="freeformTags")
    def freeform_tags(self) -> Mapping[str, Any]:
        """
        Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
        """
        return pulumi.get(self, "freeform_tags")

    @property
    @pulumi.getter
    def id(self) -> str:
        """
        Unique identifier that is immutable on creation.
        """
        return pulumi.get(self, "id")

    @property
    @pulumi.getter(name="masterMediaAssetId")
    def master_media_asset_id(self) -> str:
        """
        The ID of the senior most asset from which this asset is derived.
        """
        return pulumi.get(self, "master_media_asset_id")

    @property
    @pulumi.getter(name="mediaAssetId")
    def media_asset_id(self) -> str:
        return pulumi.get(self, "media_asset_id")

    @property
    @pulumi.getter(name="mediaAssetTags")
    def media_asset_tags(self) -> Sequence['outputs.GetMediaAssetMediaAssetTagResult']:
        """
        List of tags for the MediaAsset.
        """
        return pulumi.get(self, "media_asset_tags")

    @property
    @pulumi.getter(name="mediaWorkflowJobId")
    def media_workflow_job_id(self) -> str:
        """
        The ID of the MediaWorkflowJob used to produce this asset.
        """
        return pulumi.get(self, "media_workflow_job_id")

    @property
    @pulumi.getter
    def metadatas(self) -> Sequence['outputs.GetMediaAssetMetadataResult']:
        """
        JSON string containing the technial metadata for the media asset.
        """
        return pulumi.get(self, "metadatas")

    @property
    @pulumi.getter
    def namespace(self) -> str:
        """
        The object storage namespace where this asset is located.
        """
        return pulumi.get(self, "namespace")

    @property
    @pulumi.getter
    def object(self) -> str:
        """
        The object storage object name that identifies this asset.
        """
        return pulumi.get(self, "object")

    @property
    @pulumi.getter(name="objectEtag")
    def object_etag(self) -> str:
        """
        eTag of the underlying object storage object.
        """
        return pulumi.get(self, "object_etag")

    @property
    @pulumi.getter(name="parentMediaAssetId")
    def parent_media_asset_id(self) -> str:
        """
        The ID of the parent asset from which this asset is derived.
        """
        return pulumi.get(self, "parent_media_asset_id")

    @property
    @pulumi.getter(name="segmentRangeEndIndex")
    def segment_range_end_index(self) -> str:
        """
        The end index of video segment files.
        """
        return pulumi.get(self, "segment_range_end_index")

    @property
    @pulumi.getter(name="segmentRangeStartIndex")
    def segment_range_start_index(self) -> str:
        """
        The start index for video segment files.
        """
        return pulumi.get(self, "segment_range_start_index")

    @property
    @pulumi.getter(name="sourceMediaWorkflowId")
    def source_media_workflow_id(self) -> str:
        """
        The ID of the MediaWorkflow used to produce this asset.
        """
        return pulumi.get(self, "source_media_workflow_id")

    @property
    @pulumi.getter(name="sourceMediaWorkflowVersion")
    def source_media_workflow_version(self) -> str:
        """
        The version of the MediaWorkflow used to produce this asset.
        """
        return pulumi.get(self, "source_media_workflow_version")

    @property
    @pulumi.getter
    def state(self) -> str:
        """
        The current state of the MediaAsset.
        """
        return pulumi.get(self, "state")

    @property
    @pulumi.getter(name="systemTags")
    def system_tags(self) -> Mapping[str, Any]:
        """
        Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
        """
        return pulumi.get(self, "system_tags")

    @property
    @pulumi.getter(name="timeCreated")
    def time_created(self) -> str:
        """
        The time when the MediaAsset was created. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_created")

    @property
    @pulumi.getter(name="timeUpdated")
    def time_updated(self) -> str:
        """
        The time when the MediaAsset was updated. An RFC3339 formatted datetime string.
        """
        return pulumi.get(self, "time_updated")

    @property
    @pulumi.getter
    def type(self) -> str:
        """
        The type of the media asset.
        """
        return pulumi.get(self, "type")


class AwaitableGetMediaAssetResult(GetMediaAssetResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetMediaAssetResult(
            bucket=self.bucket,
            compartment_id=self.compartment_id,
            defined_tags=self.defined_tags,
            display_name=self.display_name,
            freeform_tags=self.freeform_tags,
            id=self.id,
            master_media_asset_id=self.master_media_asset_id,
            media_asset_id=self.media_asset_id,
            media_asset_tags=self.media_asset_tags,
            media_workflow_job_id=self.media_workflow_job_id,
            metadatas=self.metadatas,
            namespace=self.namespace,
            object=self.object,
            object_etag=self.object_etag,
            parent_media_asset_id=self.parent_media_asset_id,
            segment_range_end_index=self.segment_range_end_index,
            segment_range_start_index=self.segment_range_start_index,
            source_media_workflow_id=self.source_media_workflow_id,
            source_media_workflow_version=self.source_media_workflow_version,
            state=self.state,
            system_tags=self.system_tags,
            time_created=self.time_created,
            time_updated=self.time_updated,
            type=self.type)


def get_media_asset(media_asset_id: Optional[str] = None,
                    opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetMediaAssetResult:
    """
    This data source provides details about a specific Media Asset resource in Oracle Cloud Infrastructure Media Services service.

    Gets a MediaAsset by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_media_asset = oci.MediaServices.get_media_asset(media_asset_id=oci_media_services_media_asset["test_media_asset"]["id"])
    ```


    :param str media_asset_id: Unique MediaAsset identifier
    """
    __args__ = dict()
    __args__['mediaAssetId'] = media_asset_id
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:MediaServices/getMediaAsset:getMediaAsset', __args__, opts=opts, typ=GetMediaAssetResult).value

    return AwaitableGetMediaAssetResult(
        bucket=__ret__.bucket,
        compartment_id=__ret__.compartment_id,
        defined_tags=__ret__.defined_tags,
        display_name=__ret__.display_name,
        freeform_tags=__ret__.freeform_tags,
        id=__ret__.id,
        master_media_asset_id=__ret__.master_media_asset_id,
        media_asset_id=__ret__.media_asset_id,
        media_asset_tags=__ret__.media_asset_tags,
        media_workflow_job_id=__ret__.media_workflow_job_id,
        metadatas=__ret__.metadatas,
        namespace=__ret__.namespace,
        object=__ret__.object,
        object_etag=__ret__.object_etag,
        parent_media_asset_id=__ret__.parent_media_asset_id,
        segment_range_end_index=__ret__.segment_range_end_index,
        segment_range_start_index=__ret__.segment_range_start_index,
        source_media_workflow_id=__ret__.source_media_workflow_id,
        source_media_workflow_version=__ret__.source_media_workflow_version,
        state=__ret__.state,
        system_tags=__ret__.system_tags,
        time_created=__ret__.time_created,
        time_updated=__ret__.time_updated,
        type=__ret__.type)


@_utilities.lift_output_func(get_media_asset)
def get_media_asset_output(media_asset_id: Optional[pulumi.Input[str]] = None,
                           opts: Optional[pulumi.InvokeOptions] = None) -> pulumi.Output[GetMediaAssetResult]:
    """
    This data source provides details about a specific Media Asset resource in Oracle Cloud Infrastructure Media Services service.

    Gets a MediaAsset by identifier.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_media_asset = oci.MediaServices.get_media_asset(media_asset_id=oci_media_services_media_asset["test_media_asset"]["id"])
    ```


    :param str media_asset_id: Unique MediaAsset identifier
    """
    ...