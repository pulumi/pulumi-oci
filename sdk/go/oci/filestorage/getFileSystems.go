// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of File Systems in Oracle Cloud Infrastructure File Storage service.
//
// Lists the file system resources in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/FileStorage"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := FileStorage.GetFileSystems(ctx, &filestorage.GetFileSystemsArgs{
// 			AvailabilityDomain: _var.File_system_availability_domain,
// 			CompartmentId:      _var.Compartment_id,
// 			DisplayName:        pulumi.StringRef(_var.File_system_display_name),
// 			Id:                 pulumi.StringRef(_var.File_system_id),
// 			ParentFileSystemId: pulumi.StringRef(oci_file_storage_file_system.Test_file_system.Id),
// 			SourceSnapshotId:   pulumi.StringRef(oci_file_storage_snapshot.Test_snapshot.Id),
// 			State:              pulumi.StringRef(_var.File_system_state),
// 		}, nil)
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
func GetFileSystems(ctx *pulumi.Context, args *GetFileSystemsArgs, opts ...pulumi.InvokeOption) (*GetFileSystemsResult, error) {
	var rv GetFileSystemsResult
	err := ctx.Invoke("oci:FileStorage/getFileSystems:getFileSystems", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFileSystems.
type GetFileSystemsArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName *string                `pulumi:"displayName"`
	Filters     []GetFileSystemsFilter `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id *string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
	ParentFileSystemId *string `pulumi:"parentFileSystemId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
	SourceSnapshotId *string `pulumi:"sourceSnapshotId"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State *string `pulumi:"state"`
}

// A collection of values returned by getFileSystems.
type GetFileSystemsResult struct {
	// The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My file system`
	DisplayName *string `pulumi:"displayName"`
	// The list of file_systems.
	FileSystems []GetFileSystemsFileSystem `pulumi:"fileSystems"`
	Filters     []GetFileSystemsFilter     `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	Id *string `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
	ParentFileSystemId *string `pulumi:"parentFileSystemId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
	SourceSnapshotId *string `pulumi:"sourceSnapshotId"`
	// The current state of the file system.
	State *string `pulumi:"state"`
}

func GetFileSystemsOutput(ctx *pulumi.Context, args GetFileSystemsOutputArgs, opts ...pulumi.InvokeOption) GetFileSystemsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetFileSystemsResult, error) {
			args := v.(GetFileSystemsArgs)
			r, err := GetFileSystems(ctx, &args, opts...)
			var s GetFileSystemsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetFileSystemsResultOutput)
}

// A collection of arguments for invoking getFileSystems.
type GetFileSystemsOutputArgs struct {
	// The name of the availability domain.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringInput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. It does not have to be unique, and it is changeable.  Example: `My resource`
	DisplayName pulumi.StringPtrInput          `pulumi:"displayName"`
	Filters     GetFileSystemsFilterArrayInput `pulumi:"filters"`
	// Filter results by [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm). Must be an OCID of the correct type for the resouce type.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
	ParentFileSystemId pulumi.StringPtrInput `pulumi:"parentFileSystemId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
	SourceSnapshotId pulumi.StringPtrInput `pulumi:"sourceSnapshotId"`
	// Filter results by the specified lifecycle state. Must be a valid state for the resource type.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetFileSystemsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFileSystemsArgs)(nil)).Elem()
}

// A collection of values returned by getFileSystems.
type GetFileSystemsResultOutput struct{ *pulumi.OutputState }

func (GetFileSystemsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFileSystemsResult)(nil)).Elem()
}

func (o GetFileSystemsResultOutput) ToGetFileSystemsResultOutput() GetFileSystemsResultOutput {
	return o
}

func (o GetFileSystemsResultOutput) ToGetFileSystemsResultOutputWithContext(ctx context.Context) GetFileSystemsResultOutput {
	return o
}

// The availability domain the file system is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
func (o GetFileSystemsResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v GetFileSystemsResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the file system.
func (o GetFileSystemsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFileSystemsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My file system`
func (o GetFileSystemsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFileSystemsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

// The list of file_systems.
func (o GetFileSystemsResultOutput) FileSystems() GetFileSystemsFileSystemArrayOutput {
	return o.ApplyT(func(v GetFileSystemsResult) []GetFileSystemsFileSystem { return v.FileSystems }).(GetFileSystemsFileSystemArrayOutput)
}

func (o GetFileSystemsResultOutput) Filters() GetFileSystemsFilterArrayOutput {
	return o.ApplyT(func(v GetFileSystemsResult) []GetFileSystemsFilter { return v.Filters }).(GetFileSystemsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
func (o GetFileSystemsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFileSystemsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system that contains the source snapshot of a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
func (o GetFileSystemsResultOutput) ParentFileSystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFileSystemsResult) *string { return v.ParentFileSystemId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the source snapshot used to create a cloned file system. See [Cloning a File System](https://docs.cloud.oracle.com/iaas/Content/File/Tasks/cloningafilesystem.htm).
func (o GetFileSystemsResultOutput) SourceSnapshotId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFileSystemsResult) *string { return v.SourceSnapshotId }).(pulumi.StringPtrOutput)
}

// The current state of the file system.
func (o GetFileSystemsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFileSystemsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFileSystemsResultOutput{})
}
