// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/filestorage"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := filestorage.NewExportSet(ctx, "test_export_set", &filestorage.ExportSetArgs{
//				MountTargetId:  pulumi.Any(testMountTarget.Id),
//				DisplayName:    pulumi.Any(exportSetName),
//				MaxFsStatBytes: pulumi.String("23843202333"),
//				MaxFsStatFiles: pulumi.String("223442"),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// ExportSets can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:FileStorage/exportSet:ExportSet test_export_set "id"
// ```
type ExportSet struct {
	pulumi.CustomResourceState

	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringOutput `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes pulumi.StringOutput `pulumi:"maxFsStatBytes"`
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MaxFsStatFiles pulumi.StringOutput `pulumi:"maxFsStatFiles"`
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId pulumi.StringOutput `pulumi:"mountTargetId"`
	// The current state of the export set.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewExportSet registers a new resource with the given unique name, arguments, and options.
func NewExportSet(ctx *pulumi.Context,
	name string, args *ExportSetArgs, opts ...pulumi.ResourceOption) (*ExportSet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.MountTargetId == nil {
		return nil, errors.New("invalid value for required argument 'MountTargetId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExportSet
	err := ctx.RegisterResource("oci:FileStorage/exportSet:ExportSet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExportSet gets an existing ExportSet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExportSet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExportSetState, opts ...pulumi.ResourceOption) (*ExportSet, error) {
	var resource ExportSet
	err := ctx.ReadResource("oci:FileStorage/exportSet:ExportSet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExportSet resources.
type exportSetState struct {
	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain *string `pulumi:"availabilityDomain"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes *string `pulumi:"maxFsStatBytes"`
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MaxFsStatFiles *string `pulumi:"maxFsStatFiles"`
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId *string `pulumi:"mountTargetId"`
	// The current state of the export set.
	State *string `pulumi:"state"`
	// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
	VcnId *string `pulumi:"vcnId"`
}

type ExportSetState struct {
	// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MaxFsStatFiles pulumi.StringPtrInput
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId pulumi.StringPtrInput
	// The current state of the export set.
	State pulumi.StringPtrInput
	// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
	VcnId pulumi.StringPtrInput
}

func (ExportSetState) ElementType() reflect.Type {
	return reflect.TypeOf((*exportSetState)(nil)).Elem()
}

type exportSetArgs struct {
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes *string `pulumi:"maxFsStatBytes"`
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MaxFsStatFiles *string `pulumi:"maxFsStatFiles"`
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId string `pulumi:"mountTargetId"`
}

// The set of arguments for constructing a ExportSet resource.
type ExportSetArgs struct {
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
	DisplayName pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
	MaxFsStatBytes pulumi.StringPtrInput
	// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	MaxFsStatFiles pulumi.StringPtrInput
	// (Updatable) The OCID of the mount target that the export set is associated with
	MountTargetId pulumi.StringInput
}

func (ExportSetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*exportSetArgs)(nil)).Elem()
}

type ExportSetInput interface {
	pulumi.Input

	ToExportSetOutput() ExportSetOutput
	ToExportSetOutputWithContext(ctx context.Context) ExportSetOutput
}

func (*ExportSet) ElementType() reflect.Type {
	return reflect.TypeOf((**ExportSet)(nil)).Elem()
}

func (i *ExportSet) ToExportSetOutput() ExportSetOutput {
	return i.ToExportSetOutputWithContext(context.Background())
}

func (i *ExportSet) ToExportSetOutputWithContext(ctx context.Context) ExportSetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExportSetOutput)
}

// ExportSetArrayInput is an input type that accepts ExportSetArray and ExportSetArrayOutput values.
// You can construct a concrete instance of `ExportSetArrayInput` via:
//
//	ExportSetArray{ ExportSetArgs{...} }
type ExportSetArrayInput interface {
	pulumi.Input

	ToExportSetArrayOutput() ExportSetArrayOutput
	ToExportSetArrayOutputWithContext(context.Context) ExportSetArrayOutput
}

type ExportSetArray []ExportSetInput

func (ExportSetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExportSet)(nil)).Elem()
}

func (i ExportSetArray) ToExportSetArrayOutput() ExportSetArrayOutput {
	return i.ToExportSetArrayOutputWithContext(context.Background())
}

func (i ExportSetArray) ToExportSetArrayOutputWithContext(ctx context.Context) ExportSetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExportSetArrayOutput)
}

// ExportSetMapInput is an input type that accepts ExportSetMap and ExportSetMapOutput values.
// You can construct a concrete instance of `ExportSetMapInput` via:
//
//	ExportSetMap{ "key": ExportSetArgs{...} }
type ExportSetMapInput interface {
	pulumi.Input

	ToExportSetMapOutput() ExportSetMapOutput
	ToExportSetMapOutputWithContext(context.Context) ExportSetMapOutput
}

type ExportSetMap map[string]ExportSetInput

func (ExportSetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExportSet)(nil)).Elem()
}

func (i ExportSetMap) ToExportSetMapOutput() ExportSetMapOutput {
	return i.ToExportSetMapOutputWithContext(context.Background())
}

func (i ExportSetMap) ToExportSetMapOutputWithContext(ctx context.Context) ExportSetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExportSetMapOutput)
}

type ExportSetOutput struct{ *pulumi.OutputState }

func (ExportSetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExportSet)(nil)).Elem()
}

func (o ExportSetOutput) ToExportSetOutput() ExportSetOutput {
	return o
}

func (o ExportSetOutput) ToExportSetOutputWithContext(ctx context.Context) ExportSetOutput {
	return o
}

// The availability domain the export set is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
func (o ExportSetOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the export set.
func (o ExportSetOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My export set`
func (o ExportSetOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Controls the maximum `tbytes`, `fbytes`, and `abytes`, values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tbytes` value reported by `FSSTAT` will be `maxFsStatBytes`. The value of `fbytes` and `abytes` will be `maxFsStatBytes` minus the metered size of the file system. If the metered size is larger than `maxFsStatBytes`, then `fbytes` and `abytes` will both be '0'.
func (o ExportSetOutput) MaxFsStatBytes() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.MaxFsStatBytes }).(pulumi.StringOutput)
}

// (Updatable) Controls the maximum `tfiles`, `ffiles`, and `afiles` values reported by `NFS FSSTAT` calls through any associated mount targets. This is an advanced feature. For most applications, use the default value. The `tfiles` value reported by `FSSTAT` will be `maxFsStatFiles`. The value of `ffiles` and `afiles` will be `maxFsStatFiles` minus the metered size of the file system. If the metered size is larger than `maxFsStatFiles`, then `ffiles` and `afiles` will both be '0'.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExportSetOutput) MaxFsStatFiles() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.MaxFsStatFiles }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the mount target that the export set is associated with
func (o ExportSetOutput) MountTargetId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.MountTargetId }).(pulumi.StringOutput)
}

// The current state of the export set.
func (o ExportSetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the export set was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o ExportSetOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual cloud network (VCN) the export set is in.
func (o ExportSetOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExportSet) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

type ExportSetArrayOutput struct{ *pulumi.OutputState }

func (ExportSetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExportSet)(nil)).Elem()
}

func (o ExportSetArrayOutput) ToExportSetArrayOutput() ExportSetArrayOutput {
	return o
}

func (o ExportSetArrayOutput) ToExportSetArrayOutputWithContext(ctx context.Context) ExportSetArrayOutput {
	return o
}

func (o ExportSetArrayOutput) Index(i pulumi.IntInput) ExportSetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExportSet {
		return vs[0].([]*ExportSet)[vs[1].(int)]
	}).(ExportSetOutput)
}

type ExportSetMapOutput struct{ *pulumi.OutputState }

func (ExportSetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExportSet)(nil)).Elem()
}

func (o ExportSetMapOutput) ToExportSetMapOutput() ExportSetMapOutput {
	return o
}

func (o ExportSetMapOutput) ToExportSetMapOutputWithContext(ctx context.Context) ExportSetMapOutput {
	return o
}

func (o ExportSetMapOutput) MapIndex(k pulumi.StringInput) ExportSetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExportSet {
		return vs[0].(map[string]*ExportSet)[vs[1].(string)]
	}).(ExportSetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExportSetInput)(nil)).Elem(), &ExportSet{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExportSetArrayInput)(nil)).Elem(), ExportSetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExportSetMapInput)(nil)).Elem(), ExportSetMap{})
	pulumi.RegisterOutputType(ExportSetOutput{})
	pulumi.RegisterOutputType(ExportSetArrayOutput{})
	pulumi.RegisterOutputType(ExportSetMapOutput{})
}
