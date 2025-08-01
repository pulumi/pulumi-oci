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
    'GetJavaDownloadsJavaDownloadRecordsResult',
    'AwaitableGetJavaDownloadsJavaDownloadRecordsResult',
    'get_java_downloads_java_download_records',
    'get_java_downloads_java_download_records_output',
]

@pulumi.output_type
class GetJavaDownloadsJavaDownloadRecordsResult:
    """
    A collection of values returned by getJavaDownloadsJavaDownloadRecords.
    """
    def __init__(__self__, architecture=None, compartment_id=None, family_version=None, filters=None, id=None, java_download_record_collections=None, os_family=None, package_type_detail=None, release_version=None, time_end=None, time_start=None):
        if architecture and not isinstance(architecture, str):
            raise TypeError("Expected argument 'architecture' to be a str")
        pulumi.set(__self__, "architecture", architecture)
        if compartment_id and not isinstance(compartment_id, str):
            raise TypeError("Expected argument 'compartment_id' to be a str")
        pulumi.set(__self__, "compartment_id", compartment_id)
        if family_version and not isinstance(family_version, str):
            raise TypeError("Expected argument 'family_version' to be a str")
        pulumi.set(__self__, "family_version", family_version)
        if filters and not isinstance(filters, list):
            raise TypeError("Expected argument 'filters' to be a list")
        pulumi.set(__self__, "filters", filters)
        if id and not isinstance(id, str):
            raise TypeError("Expected argument 'id' to be a str")
        pulumi.set(__self__, "id", id)
        if java_download_record_collections and not isinstance(java_download_record_collections, list):
            raise TypeError("Expected argument 'java_download_record_collections' to be a list")
        pulumi.set(__self__, "java_download_record_collections", java_download_record_collections)
        if os_family and not isinstance(os_family, str):
            raise TypeError("Expected argument 'os_family' to be a str")
        pulumi.set(__self__, "os_family", os_family)
        if package_type_detail and not isinstance(package_type_detail, str):
            raise TypeError("Expected argument 'package_type_detail' to be a str")
        pulumi.set(__self__, "package_type_detail", package_type_detail)
        if release_version and not isinstance(release_version, str):
            raise TypeError("Expected argument 'release_version' to be a str")
        pulumi.set(__self__, "release_version", release_version)
        if time_end and not isinstance(time_end, str):
            raise TypeError("Expected argument 'time_end' to be a str")
        pulumi.set(__self__, "time_end", time_end)
        if time_start and not isinstance(time_start, str):
            raise TypeError("Expected argument 'time_start' to be a str")
        pulumi.set(__self__, "time_start", time_start)

    @_builtins.property
    @pulumi.getter
    def architecture(self) -> Optional[_builtins.str]:
        """
        The target Operating System architecture for the artifact.
        """
        return pulumi.get(self, "architecture")

    @_builtins.property
    @pulumi.getter(name="compartmentId")
    def compartment_id(self) -> _builtins.str:
        return pulumi.get(self, "compartment_id")

    @_builtins.property
    @pulumi.getter(name="familyVersion")
    def family_version(self) -> Optional[_builtins.str]:
        """
        The Java family version identifier.
        """
        return pulumi.get(self, "family_version")

    @_builtins.property
    @pulumi.getter
    def filters(self) -> Optional[Sequence['outputs.GetJavaDownloadsJavaDownloadRecordsFilterResult']]:
        return pulumi.get(self, "filters")

    @_builtins.property
    @pulumi.getter
    def id(self) -> _builtins.str:
        """
        The provider-assigned unique ID for this managed resource.
        """
        return pulumi.get(self, "id")

    @_builtins.property
    @pulumi.getter(name="javaDownloadRecordCollections")
    def java_download_record_collections(self) -> Sequence['outputs.GetJavaDownloadsJavaDownloadRecordsJavaDownloadRecordCollectionResult']:
        """
        The list of java_download_record_collection.
        """
        return pulumi.get(self, "java_download_record_collections")

    @_builtins.property
    @pulumi.getter(name="osFamily")
    def os_family(self) -> Optional[_builtins.str]:
        """
        The target Operating System family for the artifact.
        """
        return pulumi.get(self, "os_family")

    @_builtins.property
    @pulumi.getter(name="packageTypeDetail")
    def package_type_detail(self) -> Optional[_builtins.str]:
        """
        Additional information about the package type.
        """
        return pulumi.get(self, "package_type_detail")

    @_builtins.property
    @pulumi.getter(name="releaseVersion")
    def release_version(self) -> Optional[_builtins.str]:
        """
        The Java release version identifier.
        """
        return pulumi.get(self, "release_version")

    @_builtins.property
    @pulumi.getter(name="timeEnd")
    def time_end(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_end")

    @_builtins.property
    @pulumi.getter(name="timeStart")
    def time_start(self) -> Optional[_builtins.str]:
        return pulumi.get(self, "time_start")


class AwaitableGetJavaDownloadsJavaDownloadRecordsResult(GetJavaDownloadsJavaDownloadRecordsResult):
    # pylint: disable=using-constant-test
    def __await__(self):
        if False:
            yield self
        return GetJavaDownloadsJavaDownloadRecordsResult(
            architecture=self.architecture,
            compartment_id=self.compartment_id,
            family_version=self.family_version,
            filters=self.filters,
            id=self.id,
            java_download_record_collections=self.java_download_record_collections,
            os_family=self.os_family,
            package_type_detail=self.package_type_detail,
            release_version=self.release_version,
            time_end=self.time_end,
            time_start=self.time_start)


def get_java_downloads_java_download_records(architecture: Optional[_builtins.str] = None,
                                             compartment_id: Optional[_builtins.str] = None,
                                             family_version: Optional[_builtins.str] = None,
                                             filters: Optional[Sequence[Union['GetJavaDownloadsJavaDownloadRecordsFilterArgs', 'GetJavaDownloadsJavaDownloadRecordsFilterArgsDict']]] = None,
                                             os_family: Optional[_builtins.str] = None,
                                             package_type_detail: Optional[_builtins.str] = None,
                                             release_version: Optional[_builtins.str] = None,
                                             time_end: Optional[_builtins.str] = None,
                                             time_start: Optional[_builtins.str] = None,
                                             opts: Optional[pulumi.InvokeOptions] = None) -> AwaitableGetJavaDownloadsJavaDownloadRecordsResult:
    """
    This data source provides the list of Java Download Records in Oracle Cloud Infrastructure Jms Java Downloads service.

    Returns a list of Java download records in a tenancy based on specified parameters.
    See [JavaReleases API](https://docs.cloud.oracle.com/iaas/api/#/en/jms/20210610/JavaRelease/ListJavaReleases)
    for possible values of `javaFamilyVersion` and `javaReleaseVersion` parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_java_download_records = oci.Jms.get_java_downloads_java_download_records(compartment_id=compartment_id,
        architecture=java_download_record_architecture,
        family_version=java_download_record_family_version,
        os_family=java_download_record_os_family,
        package_type_detail=java_download_record_package_type_detail,
        release_version=java_download_record_release_version,
        time_end=java_download_record_time_end,
        time_start=java_download_record_time_start)
    ```


    :param _builtins.str architecture: Target Operating System architecture of the artifact.
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
    :param _builtins.str family_version: Unique Java family version identifier.
    :param _builtins.str os_family: Target Operating System family of the artifact.
    :param _builtins.str package_type_detail: Packaging type detail of the artifact.
    :param _builtins.str release_version: Unique Java release version identifier.
    :param _builtins.str time_end: The end of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
    :param _builtins.str time_start: The start of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
    """
    __args__ = dict()
    __args__['architecture'] = architecture
    __args__['compartmentId'] = compartment_id
    __args__['familyVersion'] = family_version
    __args__['filters'] = filters
    __args__['osFamily'] = os_family
    __args__['packageTypeDetail'] = package_type_detail
    __args__['releaseVersion'] = release_version
    __args__['timeEnd'] = time_end
    __args__['timeStart'] = time_start
    opts = pulumi.InvokeOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke('oci:Jms/getJavaDownloadsJavaDownloadRecords:getJavaDownloadsJavaDownloadRecords', __args__, opts=opts, typ=GetJavaDownloadsJavaDownloadRecordsResult).value

    return AwaitableGetJavaDownloadsJavaDownloadRecordsResult(
        architecture=pulumi.get(__ret__, 'architecture'),
        compartment_id=pulumi.get(__ret__, 'compartment_id'),
        family_version=pulumi.get(__ret__, 'family_version'),
        filters=pulumi.get(__ret__, 'filters'),
        id=pulumi.get(__ret__, 'id'),
        java_download_record_collections=pulumi.get(__ret__, 'java_download_record_collections'),
        os_family=pulumi.get(__ret__, 'os_family'),
        package_type_detail=pulumi.get(__ret__, 'package_type_detail'),
        release_version=pulumi.get(__ret__, 'release_version'),
        time_end=pulumi.get(__ret__, 'time_end'),
        time_start=pulumi.get(__ret__, 'time_start'))
def get_java_downloads_java_download_records_output(architecture: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    compartment_id: Optional[pulumi.Input[_builtins.str]] = None,
                                                    family_version: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    filters: Optional[pulumi.Input[Optional[Sequence[Union['GetJavaDownloadsJavaDownloadRecordsFilterArgs', 'GetJavaDownloadsJavaDownloadRecordsFilterArgsDict']]]]] = None,
                                                    os_family: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    package_type_detail: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    release_version: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    time_end: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    time_start: Optional[pulumi.Input[Optional[_builtins.str]]] = None,
                                                    opts: Optional[Union[pulumi.InvokeOptions, pulumi.InvokeOutputOptions]] = None) -> pulumi.Output[GetJavaDownloadsJavaDownloadRecordsResult]:
    """
    This data source provides the list of Java Download Records in Oracle Cloud Infrastructure Jms Java Downloads service.

    Returns a list of Java download records in a tenancy based on specified parameters.
    See [JavaReleases API](https://docs.cloud.oracle.com/iaas/api/#/en/jms/20210610/JavaRelease/ListJavaReleases)
    for possible values of `javaFamilyVersion` and `javaReleaseVersion` parameters.

    ## Example Usage

    ```python
    import pulumi
    import pulumi_oci as oci

    test_java_download_records = oci.Jms.get_java_downloads_java_download_records(compartment_id=compartment_id,
        architecture=java_download_record_architecture,
        family_version=java_download_record_family_version,
        os_family=java_download_record_os_family,
        package_type_detail=java_download_record_package_type_detail,
        release_version=java_download_record_release_version,
        time_end=java_download_record_time_end,
        time_start=java_download_record_time_start)
    ```


    :param _builtins.str architecture: Target Operating System architecture of the artifact.
    :param _builtins.str compartment_id: The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the tenancy.
    :param _builtins.str family_version: Unique Java family version identifier.
    :param _builtins.str os_family: Target Operating System family of the artifact.
    :param _builtins.str package_type_detail: Packaging type detail of the artifact.
    :param _builtins.str release_version: Unique Java release version identifier.
    :param _builtins.str time_end: The end of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
    :param _builtins.str time_start: The start of the time period for which reports are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
    """
    __args__ = dict()
    __args__['architecture'] = architecture
    __args__['compartmentId'] = compartment_id
    __args__['familyVersion'] = family_version
    __args__['filters'] = filters
    __args__['osFamily'] = os_family
    __args__['packageTypeDetail'] = package_type_detail
    __args__['releaseVersion'] = release_version
    __args__['timeEnd'] = time_end
    __args__['timeStart'] = time_start
    opts = pulumi.InvokeOutputOptions.merge(_utilities.get_invoke_opts_defaults(), opts)
    __ret__ = pulumi.runtime.invoke_output('oci:Jms/getJavaDownloadsJavaDownloadRecords:getJavaDownloadsJavaDownloadRecords', __args__, opts=opts, typ=GetJavaDownloadsJavaDownloadRecordsResult)
    return __ret__.apply(lambda __response__: GetJavaDownloadsJavaDownloadRecordsResult(
        architecture=pulumi.get(__response__, 'architecture'),
        compartment_id=pulumi.get(__response__, 'compartment_id'),
        family_version=pulumi.get(__response__, 'family_version'),
        filters=pulumi.get(__response__, 'filters'),
        id=pulumi.get(__response__, 'id'),
        java_download_record_collections=pulumi.get(__response__, 'java_download_record_collections'),
        os_family=pulumi.get(__response__, 'os_family'),
        package_type_detail=pulumi.get(__response__, 'package_type_detail'),
        release_version=pulumi.get(__response__, 'release_version'),
        time_end=pulumi.get(__response__, 'time_end'),
        time_start=pulumi.get(__response__, 'time_start')))
