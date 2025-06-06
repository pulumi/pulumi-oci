// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Tag resource in Oracle Cloud Infrastructure Identity service.
//
// Gets the specified tag's information.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := identity.GetTag(ctx, &identity.GetTagArgs{
//				TagName:        testTagOciIdentityTag.Name,
//				TagNamespaceId: testTagNamespace.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupTag(ctx *pulumi.Context, args *LookupTagArgs, opts ...pulumi.InvokeOption) (*LookupTagResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupTagResult
	err := ctx.Invoke("oci:Identity/getTag:getTag", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTag.
type LookupTagArgs struct {
	// The name of the tag.
	TagName string `pulumi:"tagName"`
	// The OCID of the tag namespace.
	TagNamespaceId string `pulumi:"tagNamespaceId"`
}

// A collection of values returned by getTag.
type LookupTagResult struct {
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// The description you assign to the tag.
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the tag definition.
	Id string `pulumi:"id"`
	// Indicates whether the tag is enabled for cost tracking.
	IsCostTracking bool `pulumi:"isCostTracking"`
	// Indicates whether the tag is retired. See [Retiring Key Definitions and Namespace Definitions](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#Retiring).
	IsRetired bool `pulumi:"isRetired"`
	// The name assigned to the tag during creation. This is the tag key definition. The name must be unique within the tag namespace and cannot be changed.
	Name string `pulumi:"name"`
	// The tag's current state. After creating a tag, make sure its `lifecycleState` is ACTIVE before using it. After retiring a tag, make sure its `lifecycleState` is INACTIVE before using it. If you delete a tag, you cannot delete another tag until the deleted tag's `lifecycleState` changes from DELETING to DELETED.
	State   string `pulumi:"state"`
	TagName string `pulumi:"tagName"`
	// The OCID of the namespace that contains the tag definition.
	TagNamespaceId string `pulumi:"tagNamespaceId"`
	// Date and time the tag was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// Validates a definedTag value. Each validator performs validation steps in addition to the standard validation for definedTag values. For more information, see [Limits on Tags](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#Limits).
	Validators []GetTagValidator `pulumi:"validators"`
}

func LookupTagOutput(ctx *pulumi.Context, args LookupTagOutputArgs, opts ...pulumi.InvokeOption) LookupTagResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupTagResultOutput, error) {
			args := v.(LookupTagArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Identity/getTag:getTag", args, LookupTagResultOutput{}, options).(LookupTagResultOutput), nil
		}).(LookupTagResultOutput)
}

// A collection of arguments for invoking getTag.
type LookupTagOutputArgs struct {
	// The name of the tag.
	TagName pulumi.StringInput `pulumi:"tagName"`
	// The OCID of the tag namespace.
	TagNamespaceId pulumi.StringInput `pulumi:"tagNamespaceId"`
}

func (LookupTagOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupTagArgs)(nil)).Elem()
}

// A collection of values returned by getTag.
type LookupTagResultOutput struct{ *pulumi.OutputState }

func (LookupTagResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupTagResult)(nil)).Elem()
}

func (o LookupTagResultOutput) ToLookupTagResultOutput() LookupTagResultOutput {
	return o
}

func (o LookupTagResultOutput) ToLookupTagResultOutputWithContext(ctx context.Context) LookupTagResultOutput {
	return o
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupTagResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupTagResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// The description you assign to the tag.
func (o LookupTagResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.Description }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupTagResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupTagResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the tag definition.
func (o LookupTagResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates whether the tag is enabled for cost tracking.
func (o LookupTagResultOutput) IsCostTracking() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupTagResult) bool { return v.IsCostTracking }).(pulumi.BoolOutput)
}

// Indicates whether the tag is retired. See [Retiring Key Definitions and Namespace Definitions](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#Retiring).
func (o LookupTagResultOutput) IsRetired() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupTagResult) bool { return v.IsRetired }).(pulumi.BoolOutput)
}

// The name assigned to the tag during creation. This is the tag key definition. The name must be unique within the tag namespace and cannot be changed.
func (o LookupTagResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.Name }).(pulumi.StringOutput)
}

// The tag's current state. After creating a tag, make sure its `lifecycleState` is ACTIVE before using it. After retiring a tag, make sure its `lifecycleState` is INACTIVE before using it. If you delete a tag, you cannot delete another tag until the deleted tag's `lifecycleState` changes from DELETING to DELETED.
func (o LookupTagResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.State }).(pulumi.StringOutput)
}

func (o LookupTagResultOutput) TagName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.TagName }).(pulumi.StringOutput)
}

// The OCID of the namespace that contains the tag definition.
func (o LookupTagResultOutput) TagNamespaceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.TagNamespaceId }).(pulumi.StringOutput)
}

// Date and time the tag was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
func (o LookupTagResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupTagResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// Validates a definedTag value. Each validator performs validation steps in addition to the standard validation for definedTag values. For more information, see [Limits on Tags](https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/taggingoverview.htm#Limits).
func (o LookupTagResultOutput) Validators() GetTagValidatorArrayOutput {
	return o.ApplyT(func(v LookupTagResult) []GetTagValidator { return v.Validators }).(GetTagValidatorArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupTagResultOutput{})
}
