// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Export resource in Oracle Cloud Infrastructure File Storage service.
//
// Creates a new export in the specified export set, path, and
// file system.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/FileStorage"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := FileStorage.NewExport(ctx, "testExport", &FileStorage.ExportArgs{
//				ExportSetId:  pulumi.Any(oci_file_storage_export_set.Test_export_set.Id),
//				FileSystemId: pulumi.Any(oci_file_storage_file_system.Test_file_system.Id),
//				Path:         pulumi.Any(_var.Export_path),
//				ExportOptions: filestorage.ExportExportOptionArray{
//					&filestorage.ExportExportOptionArgs{
//						Source:                      pulumi.Any(_var.Export_export_options_source),
//						Access:                      pulumi.Any(_var.Export_export_options_access),
//						AnonymousGid:                pulumi.Any(_var.Export_export_options_anonymous_gid),
//						AnonymousUid:                pulumi.Any(_var.Export_export_options_anonymous_uid),
//						IdentitySquash:              pulumi.Any(_var.Export_export_options_identity_squash),
//						RequirePrivilegedSourcePort: pulumi.Any(_var.Export_export_options_require_privileged_source_port),
//					},
//				},
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
// Exports can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:FileStorage/export:Export test_export "id"
//
// ```
type Export struct {
	pulumi.CustomResourceState

	// (Updatable) Export options for the new export. If left unspecified, defaults to:
	ExportOptions ExportExportOptionArrayOutput `pulumi:"exportOptions"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
	ExportSetId pulumi.StringOutput `pulumi:"exportSetId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
	FileSystemId pulumi.StringOutput `pulumi:"fileSystemId"`
	// Path used to access the associated file system.
	Path pulumi.StringOutput `pulumi:"path"`
	// The current state of this export.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewExport registers a new resource with the given unique name, arguments, and options.
func NewExport(ctx *pulumi.Context,
	name string, args *ExportArgs, opts ...pulumi.ResourceOption) (*Export, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ExportSetId == nil {
		return nil, errors.New("invalid value for required argument 'ExportSetId'")
	}
	if args.FileSystemId == nil {
		return nil, errors.New("invalid value for required argument 'FileSystemId'")
	}
	if args.Path == nil {
		return nil, errors.New("invalid value for required argument 'Path'")
	}
	var resource Export
	err := ctx.RegisterResource("oci:FileStorage/export:Export", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExport gets an existing Export resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExport(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExportState, opts ...pulumi.ResourceOption) (*Export, error) {
	var resource Export
	err := ctx.ReadResource("oci:FileStorage/export:Export", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Export resources.
type exportState struct {
	// (Updatable) Export options for the new export. If left unspecified, defaults to:
	ExportOptions []ExportExportOption `pulumi:"exportOptions"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
	ExportSetId *string `pulumi:"exportSetId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
	FileSystemId *string `pulumi:"fileSystemId"`
	// Path used to access the associated file system.
	Path *string `pulumi:"path"`
	// The current state of this export.
	State *string `pulumi:"state"`
	// The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
}

type ExportState struct {
	// (Updatable) Export options for the new export. If left unspecified, defaults to:
	ExportOptions ExportExportOptionArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
	ExportSetId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
	FileSystemId pulumi.StringPtrInput
	// Path used to access the associated file system.
	Path pulumi.StringPtrInput
	// The current state of this export.
	State pulumi.StringPtrInput
	// The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
}

func (ExportState) ElementType() reflect.Type {
	return reflect.TypeOf((*exportState)(nil)).Elem()
}

type exportArgs struct {
	// (Updatable) Export options for the new export. If left unspecified, defaults to:
	ExportOptions []ExportExportOption `pulumi:"exportOptions"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
	ExportSetId string `pulumi:"exportSetId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
	FileSystemId string `pulumi:"fileSystemId"`
	// Path used to access the associated file system.
	Path string `pulumi:"path"`
}

// The set of arguments for constructing a Export resource.
type ExportArgs struct {
	// (Updatable) Export options for the new export. If left unspecified, defaults to:
	ExportOptions ExportExportOptionArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
	ExportSetId pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
	FileSystemId pulumi.StringInput
	// Path used to access the associated file system.
	Path pulumi.StringInput
}

func (ExportArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*exportArgs)(nil)).Elem()
}

type ExportInput interface {
	pulumi.Input

	ToExportOutput() ExportOutput
	ToExportOutputWithContext(ctx context.Context) ExportOutput
}

func (*Export) ElementType() reflect.Type {
	return reflect.TypeOf((**Export)(nil)).Elem()
}

func (i *Export) ToExportOutput() ExportOutput {
	return i.ToExportOutputWithContext(context.Background())
}

func (i *Export) ToExportOutputWithContext(ctx context.Context) ExportOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExportOutput)
}

// ExportArrayInput is an input type that accepts ExportArray and ExportArrayOutput values.
// You can construct a concrete instance of `ExportArrayInput` via:
//
//	ExportArray{ ExportArgs{...} }
type ExportArrayInput interface {
	pulumi.Input

	ToExportArrayOutput() ExportArrayOutput
	ToExportArrayOutputWithContext(context.Context) ExportArrayOutput
}

type ExportArray []ExportInput

func (ExportArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Export)(nil)).Elem()
}

func (i ExportArray) ToExportArrayOutput() ExportArrayOutput {
	return i.ToExportArrayOutputWithContext(context.Background())
}

func (i ExportArray) ToExportArrayOutputWithContext(ctx context.Context) ExportArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExportArrayOutput)
}

// ExportMapInput is an input type that accepts ExportMap and ExportMapOutput values.
// You can construct a concrete instance of `ExportMapInput` via:
//
//	ExportMap{ "key": ExportArgs{...} }
type ExportMapInput interface {
	pulumi.Input

	ToExportMapOutput() ExportMapOutput
	ToExportMapOutputWithContext(context.Context) ExportMapOutput
}

type ExportMap map[string]ExportInput

func (ExportMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Export)(nil)).Elem()
}

func (i ExportMap) ToExportMapOutput() ExportMapOutput {
	return i.ToExportMapOutputWithContext(context.Background())
}

func (i ExportMap) ToExportMapOutputWithContext(ctx context.Context) ExportMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExportMapOutput)
}

type ExportOutput struct{ *pulumi.OutputState }

func (ExportOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Export)(nil)).Elem()
}

func (o ExportOutput) ToExportOutput() ExportOutput {
	return o
}

func (o ExportOutput) ToExportOutputWithContext(ctx context.Context) ExportOutput {
	return o
}

// (Updatable) Export options for the new export. If left unspecified, defaults to:
func (o ExportOutput) ExportOptions() ExportExportOptionArrayOutput {
	return o.ApplyT(func(v *Export) ExportExportOptionArrayOutput { return v.ExportOptions }).(ExportExportOptionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's export set.
func (o ExportOutput) ExportSetId() pulumi.StringOutput {
	return o.ApplyT(func(v *Export) pulumi.StringOutput { return v.ExportSetId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of this export's file system.
func (o ExportOutput) FileSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v *Export) pulumi.StringOutput { return v.FileSystemId }).(pulumi.StringOutput)
}

// Path used to access the associated file system.
func (o ExportOutput) Path() pulumi.StringOutput {
	return o.ApplyT(func(v *Export) pulumi.StringOutput { return v.Path }).(pulumi.StringOutput)
}

// The current state of this export.
func (o ExportOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Export) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the export was created, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o ExportOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Export) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type ExportArrayOutput struct{ *pulumi.OutputState }

func (ExportArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Export)(nil)).Elem()
}

func (o ExportArrayOutput) ToExportArrayOutput() ExportArrayOutput {
	return o
}

func (o ExportArrayOutput) ToExportArrayOutputWithContext(ctx context.Context) ExportArrayOutput {
	return o
}

func (o ExportArrayOutput) Index(i pulumi.IntInput) ExportOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Export {
		return vs[0].([]*Export)[vs[1].(int)]
	}).(ExportOutput)
}

type ExportMapOutput struct{ *pulumi.OutputState }

func (ExportMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Export)(nil)).Elem()
}

func (o ExportMapOutput) ToExportMapOutput() ExportMapOutput {
	return o
}

func (o ExportMapOutput) ToExportMapOutputWithContext(ctx context.Context) ExportMapOutput {
	return o
}

func (o ExportMapOutput) MapIndex(k pulumi.StringInput) ExportOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Export {
		return vs[0].(map[string]*Export)[vs[1].(string)]
	}).(ExportOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExportInput)(nil)).Elem(), &Export{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExportArrayInput)(nil)).Elem(), ExportArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExportMapInput)(nil)).Elem(), ExportMap{})
	pulumi.RegisterOutputType(ExportOutput{})
	pulumi.RegisterOutputType(ExportArrayOutput{})
	pulumi.RegisterOutputType(ExportMapOutput{})
}