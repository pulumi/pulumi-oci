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

// This resource provides the File System Quota Rule resource in Oracle Cloud Infrastructure File Storage service.
//
// Create an FS level, user or group quota rule given the `fileSystemId`, `principalId`, `principalType` and
// `isHardQuota` parameters.
//
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
//			_, err := filestorage.NewFileSystemQuotaRule(ctx, "test_file_system_quota_rule", &filestorage.FileSystemQuotaRuleArgs{
//				FileSystemId:          pulumi.Any(testFileSystem.Id),
//				IsHardQuota:           pulumi.Any(fileSystemQuotaRuleIsHardQuota),
//				PrincipalType:         pulumi.Any(fileSystemQuotaRulePrincipalType),
//				QuotaLimitInGigabytes: pulumi.Any(fileSystemQuotaRuleQuotaLimitInGigabytes),
//				DisplayName:           pulumi.Any(fileSystemQuotaRuleDisplayName),
//				PrincipalId:           pulumi.Any(testPrincipal.Id),
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
// FileSystemQuotaRules can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:FileStorage/fileSystemQuotaRule:FileSystemQuotaRule test_file_system_quota_rule "fileSystems/{fileSystemId}/quotaRules/{quotaRuleId}"
// ```
type FileSystemQuotaRule struct {
	pulumi.CustomResourceState

	AreViolatorsOnly pulumi.BoolPtrOutput `pulumi:"areViolatorsOnly"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId pulumi.StringOutput `pulumi:"fileSystemId"`
	// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is true, the quota rule will be enforced so the write will be blocked if usage exceeds the hard quota limit. If `isHardQuota` is false, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
	IsHardQuota pulumi.BoolOutput `pulumi:"isHardQuota"`
	// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
	PrincipalId pulumi.IntOutput `pulumi:"principalId"`
	// The type of the owner of this quota rule and usage.
	PrincipalType pulumi.StringOutput `pulumi:"principalType"`
	// (Updatable) The value of the quota rule. The unit is Gigabyte.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	QuotaLimitInGigabytes pulumi.IntOutput    `pulumi:"quotaLimitInGigabytes"`
	QuotaRuleId           pulumi.StringOutput `pulumi:"quotaRuleId"`
	// The date and time the quota rule was started, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the quota rule was last updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewFileSystemQuotaRule registers a new resource with the given unique name, arguments, and options.
func NewFileSystemQuotaRule(ctx *pulumi.Context,
	name string, args *FileSystemQuotaRuleArgs, opts ...pulumi.ResourceOption) (*FileSystemQuotaRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.FileSystemId == nil {
		return nil, errors.New("invalid value for required argument 'FileSystemId'")
	}
	if args.IsHardQuota == nil {
		return nil, errors.New("invalid value for required argument 'IsHardQuota'")
	}
	if args.PrincipalType == nil {
		return nil, errors.New("invalid value for required argument 'PrincipalType'")
	}
	if args.QuotaLimitInGigabytes == nil {
		return nil, errors.New("invalid value for required argument 'QuotaLimitInGigabytes'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource FileSystemQuotaRule
	err := ctx.RegisterResource("oci:FileStorage/fileSystemQuotaRule:FileSystemQuotaRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetFileSystemQuotaRule gets an existing FileSystemQuotaRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetFileSystemQuotaRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *FileSystemQuotaRuleState, opts ...pulumi.ResourceOption) (*FileSystemQuotaRule, error) {
	var resource FileSystemQuotaRule
	err := ctx.ReadResource("oci:FileStorage/fileSystemQuotaRule:FileSystemQuotaRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering FileSystemQuotaRule resources.
type fileSystemQuotaRuleState struct {
	AreViolatorsOnly *bool `pulumi:"areViolatorsOnly"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId *string `pulumi:"fileSystemId"`
	// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is true, the quota rule will be enforced so the write will be blocked if usage exceeds the hard quota limit. If `isHardQuota` is false, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
	IsHardQuota *bool `pulumi:"isHardQuota"`
	// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
	PrincipalId *int `pulumi:"principalId"`
	// The type of the owner of this quota rule and usage.
	PrincipalType *string `pulumi:"principalType"`
	// (Updatable) The value of the quota rule. The unit is Gigabyte.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	QuotaLimitInGigabytes *int    `pulumi:"quotaLimitInGigabytes"`
	QuotaRuleId           *string `pulumi:"quotaRuleId"`
	// The date and time the quota rule was started, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the quota rule was last updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type FileSystemQuotaRuleState struct {
	AreViolatorsOnly pulumi.BoolPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId pulumi.StringPtrInput
	// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is true, the quota rule will be enforced so the write will be blocked if usage exceeds the hard quota limit. If `isHardQuota` is false, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
	IsHardQuota pulumi.BoolPtrInput
	// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
	PrincipalId pulumi.IntPtrInput
	// The type of the owner of this quota rule and usage.
	PrincipalType pulumi.StringPtrInput
	// (Updatable) The value of the quota rule. The unit is Gigabyte.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	QuotaLimitInGigabytes pulumi.IntPtrInput
	QuotaRuleId           pulumi.StringPtrInput
	// The date and time the quota rule was started, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated pulumi.StringPtrInput
	// The date and time the quota rule was last updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeUpdated pulumi.StringPtrInput
}

func (FileSystemQuotaRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*fileSystemQuotaRuleState)(nil)).Elem()
}

type fileSystemQuotaRuleArgs struct {
	AreViolatorsOnly *bool `pulumi:"areViolatorsOnly"`
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
	DisplayName *string `pulumi:"displayName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId string `pulumi:"fileSystemId"`
	// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is true, the quota rule will be enforced so the write will be blocked if usage exceeds the hard quota limit. If `isHardQuota` is false, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
	IsHardQuota bool `pulumi:"isHardQuota"`
	// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
	PrincipalId *int `pulumi:"principalId"`
	// The type of the owner of this quota rule and usage.
	PrincipalType string `pulumi:"principalType"`
	// (Updatable) The value of the quota rule. The unit is Gigabyte.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	QuotaLimitInGigabytes int     `pulumi:"quotaLimitInGigabytes"`
	QuotaRuleId           *string `pulumi:"quotaRuleId"`
}

// The set of arguments for constructing a FileSystemQuotaRule resource.
type FileSystemQuotaRuleArgs struct {
	AreViolatorsOnly pulumi.BoolPtrInput
	// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
	DisplayName pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
	FileSystemId pulumi.StringInput
	// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is true, the quota rule will be enforced so the write will be blocked if usage exceeds the hard quota limit. If `isHardQuota` is false, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
	IsHardQuota pulumi.BoolInput
	// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
	PrincipalId pulumi.IntPtrInput
	// The type of the owner of this quota rule and usage.
	PrincipalType pulumi.StringInput
	// (Updatable) The value of the quota rule. The unit is Gigabyte.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	QuotaLimitInGigabytes pulumi.IntInput
	QuotaRuleId           pulumi.StringPtrInput
}

func (FileSystemQuotaRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*fileSystemQuotaRuleArgs)(nil)).Elem()
}

type FileSystemQuotaRuleInput interface {
	pulumi.Input

	ToFileSystemQuotaRuleOutput() FileSystemQuotaRuleOutput
	ToFileSystemQuotaRuleOutputWithContext(ctx context.Context) FileSystemQuotaRuleOutput
}

func (*FileSystemQuotaRule) ElementType() reflect.Type {
	return reflect.TypeOf((**FileSystemQuotaRule)(nil)).Elem()
}

func (i *FileSystemQuotaRule) ToFileSystemQuotaRuleOutput() FileSystemQuotaRuleOutput {
	return i.ToFileSystemQuotaRuleOutputWithContext(context.Background())
}

func (i *FileSystemQuotaRule) ToFileSystemQuotaRuleOutputWithContext(ctx context.Context) FileSystemQuotaRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileSystemQuotaRuleOutput)
}

// FileSystemQuotaRuleArrayInput is an input type that accepts FileSystemQuotaRuleArray and FileSystemQuotaRuleArrayOutput values.
// You can construct a concrete instance of `FileSystemQuotaRuleArrayInput` via:
//
//	FileSystemQuotaRuleArray{ FileSystemQuotaRuleArgs{...} }
type FileSystemQuotaRuleArrayInput interface {
	pulumi.Input

	ToFileSystemQuotaRuleArrayOutput() FileSystemQuotaRuleArrayOutput
	ToFileSystemQuotaRuleArrayOutputWithContext(context.Context) FileSystemQuotaRuleArrayOutput
}

type FileSystemQuotaRuleArray []FileSystemQuotaRuleInput

func (FileSystemQuotaRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FileSystemQuotaRule)(nil)).Elem()
}

func (i FileSystemQuotaRuleArray) ToFileSystemQuotaRuleArrayOutput() FileSystemQuotaRuleArrayOutput {
	return i.ToFileSystemQuotaRuleArrayOutputWithContext(context.Background())
}

func (i FileSystemQuotaRuleArray) ToFileSystemQuotaRuleArrayOutputWithContext(ctx context.Context) FileSystemQuotaRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileSystemQuotaRuleArrayOutput)
}

// FileSystemQuotaRuleMapInput is an input type that accepts FileSystemQuotaRuleMap and FileSystemQuotaRuleMapOutput values.
// You can construct a concrete instance of `FileSystemQuotaRuleMapInput` via:
//
//	FileSystemQuotaRuleMap{ "key": FileSystemQuotaRuleArgs{...} }
type FileSystemQuotaRuleMapInput interface {
	pulumi.Input

	ToFileSystemQuotaRuleMapOutput() FileSystemQuotaRuleMapOutput
	ToFileSystemQuotaRuleMapOutputWithContext(context.Context) FileSystemQuotaRuleMapOutput
}

type FileSystemQuotaRuleMap map[string]FileSystemQuotaRuleInput

func (FileSystemQuotaRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FileSystemQuotaRule)(nil)).Elem()
}

func (i FileSystemQuotaRuleMap) ToFileSystemQuotaRuleMapOutput() FileSystemQuotaRuleMapOutput {
	return i.ToFileSystemQuotaRuleMapOutputWithContext(context.Background())
}

func (i FileSystemQuotaRuleMap) ToFileSystemQuotaRuleMapOutputWithContext(ctx context.Context) FileSystemQuotaRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(FileSystemQuotaRuleMapOutput)
}

type FileSystemQuotaRuleOutput struct{ *pulumi.OutputState }

func (FileSystemQuotaRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**FileSystemQuotaRule)(nil)).Elem()
}

func (o FileSystemQuotaRuleOutput) ToFileSystemQuotaRuleOutput() FileSystemQuotaRuleOutput {
	return o
}

func (o FileSystemQuotaRuleOutput) ToFileSystemQuotaRuleOutputWithContext(ctx context.Context) FileSystemQuotaRuleOutput {
	return o
}

func (o FileSystemQuotaRuleOutput) AreViolatorsOnly() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.BoolPtrOutput { return v.AreViolatorsOnly }).(pulumi.BoolPtrOutput)
}

// (Updatable) A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information. Example: `UserXYZ's quota`
func (o FileSystemQuotaRuleOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the file system.
func (o FileSystemQuotaRuleOutput) FileSystemId() pulumi.StringOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.StringOutput { return v.FileSystemId }).(pulumi.StringOutput)
}

// The flag is an identifier to tell whether the quota rule will be enforced. If `isHardQuota` is true, the quota rule will be enforced so the write will be blocked if usage exceeds the hard quota limit. If `isHardQuota` is false, usage can exceed the soft quota limit. An alarm or notification will be sent to the customer, if the specific usage exceeds.
func (o FileSystemQuotaRuleOutput) IsHardQuota() pulumi.BoolOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.BoolOutput { return v.IsHardQuota }).(pulumi.BoolOutput)
}

// An identifier for the owner of this usage and quota rule. Unix-like operating systems use this integer value to identify a user or group to manage access control.
func (o FileSystemQuotaRuleOutput) PrincipalId() pulumi.IntOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.IntOutput { return v.PrincipalId }).(pulumi.IntOutput)
}

// The type of the owner of this quota rule and usage.
func (o FileSystemQuotaRuleOutput) PrincipalType() pulumi.StringOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.StringOutput { return v.PrincipalType }).(pulumi.StringOutput)
}

// (Updatable) The value of the quota rule. The unit is Gigabyte.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o FileSystemQuotaRuleOutput) QuotaLimitInGigabytes() pulumi.IntOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.IntOutput { return v.QuotaLimitInGigabytes }).(pulumi.IntOutput)
}

func (o FileSystemQuotaRuleOutput) QuotaRuleId() pulumi.StringOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.StringOutput { return v.QuotaRuleId }).(pulumi.StringOutput)
}

// The date and time the quota rule was started, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o FileSystemQuotaRuleOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the quota rule was last updated, expressed in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o FileSystemQuotaRuleOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *FileSystemQuotaRule) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type FileSystemQuotaRuleArrayOutput struct{ *pulumi.OutputState }

func (FileSystemQuotaRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*FileSystemQuotaRule)(nil)).Elem()
}

func (o FileSystemQuotaRuleArrayOutput) ToFileSystemQuotaRuleArrayOutput() FileSystemQuotaRuleArrayOutput {
	return o
}

func (o FileSystemQuotaRuleArrayOutput) ToFileSystemQuotaRuleArrayOutputWithContext(ctx context.Context) FileSystemQuotaRuleArrayOutput {
	return o
}

func (o FileSystemQuotaRuleArrayOutput) Index(i pulumi.IntInput) FileSystemQuotaRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *FileSystemQuotaRule {
		return vs[0].([]*FileSystemQuotaRule)[vs[1].(int)]
	}).(FileSystemQuotaRuleOutput)
}

type FileSystemQuotaRuleMapOutput struct{ *pulumi.OutputState }

func (FileSystemQuotaRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*FileSystemQuotaRule)(nil)).Elem()
}

func (o FileSystemQuotaRuleMapOutput) ToFileSystemQuotaRuleMapOutput() FileSystemQuotaRuleMapOutput {
	return o
}

func (o FileSystemQuotaRuleMapOutput) ToFileSystemQuotaRuleMapOutputWithContext(ctx context.Context) FileSystemQuotaRuleMapOutput {
	return o
}

func (o FileSystemQuotaRuleMapOutput) MapIndex(k pulumi.StringInput) FileSystemQuotaRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *FileSystemQuotaRule {
		return vs[0].(map[string]*FileSystemQuotaRule)[vs[1].(string)]
	}).(FileSystemQuotaRuleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*FileSystemQuotaRuleInput)(nil)).Elem(), &FileSystemQuotaRule{})
	pulumi.RegisterInputType(reflect.TypeOf((*FileSystemQuotaRuleArrayInput)(nil)).Elem(), FileSystemQuotaRuleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*FileSystemQuotaRuleMapInput)(nil)).Elem(), FileSystemQuotaRuleMap{})
	pulumi.RegisterOutputType(FileSystemQuotaRuleOutput{})
	pulumi.RegisterOutputType(FileSystemQuotaRuleArrayOutput{})
	pulumi.RegisterOutputType(FileSystemQuotaRuleMapOutput{})
}
