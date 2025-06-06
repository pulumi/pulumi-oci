// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package certificatesmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Ca Bundle resource in Oracle Cloud Infrastructure Certificates Management service.
//
// Gets details about the specified CA bundle.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/certificatesmanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := certificatesmanagement.GetCaBundle(ctx, &certificatesmanagement.GetCaBundleArgs{
//				CaBundleId: testCaBundleOciCertificatesManagementCaBundle.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupCaBundle(ctx *pulumi.Context, args *LookupCaBundleArgs, opts ...pulumi.InvokeOption) (*LookupCaBundleResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupCaBundleResult
	err := ctx.Invoke("oci:CertificatesManagement/getCaBundle:getCaBundle", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCaBundle.
type LookupCaBundleArgs struct {
	// The OCID of the CA bundle.
	CaBundleId string `pulumi:"caBundleId"`
}

// A collection of values returned by getCaBundle.
type LookupCaBundleResult struct {
	CaBundleId  string `pulumi:"caBundleId"`
	CaBundlePem string `pulumi:"caBundlePem"`
	// The OCID of the compartment for the CA bundle.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A brief description of the CA bundle.
	Description string `pulumi:"description"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the CA bundle.
	Id string `pulumi:"id"`
	// Additional information about the current lifecycle state of the CA bundle.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// A user-friendly name for the CA bundle. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name string `pulumi:"name"`
	// The current lifecycle state of the CA bundle.
	State string `pulumi:"state"`
	// A property indicating when the CA bundle was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupCaBundleOutput(ctx *pulumi.Context, args LookupCaBundleOutputArgs, opts ...pulumi.InvokeOption) LookupCaBundleResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupCaBundleResultOutput, error) {
			args := v.(LookupCaBundleArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CertificatesManagement/getCaBundle:getCaBundle", args, LookupCaBundleResultOutput{}, options).(LookupCaBundleResultOutput), nil
		}).(LookupCaBundleResultOutput)
}

// A collection of arguments for invoking getCaBundle.
type LookupCaBundleOutputArgs struct {
	// The OCID of the CA bundle.
	CaBundleId pulumi.StringInput `pulumi:"caBundleId"`
}

func (LookupCaBundleOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupCaBundleArgs)(nil)).Elem()
}

// A collection of values returned by getCaBundle.
type LookupCaBundleResultOutput struct{ *pulumi.OutputState }

func (LookupCaBundleResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupCaBundleResult)(nil)).Elem()
}

func (o LookupCaBundleResultOutput) ToLookupCaBundleResultOutput() LookupCaBundleResultOutput {
	return o
}

func (o LookupCaBundleResultOutput) ToLookupCaBundleResultOutputWithContext(ctx context.Context) LookupCaBundleResultOutput {
	return o
}

func (o LookupCaBundleResultOutput) CaBundleId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.CaBundleId }).(pulumi.StringOutput)
}

func (o LookupCaBundleResultOutput) CaBundlePem() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.CaBundlePem }).(pulumi.StringOutput)
}

// The OCID of the compartment for the CA bundle.
func (o LookupCaBundleResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupCaBundleResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupCaBundleResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A brief description of the CA bundle.
func (o LookupCaBundleResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.Description }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupCaBundleResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupCaBundleResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the CA bundle.
func (o LookupCaBundleResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.Id }).(pulumi.StringOutput)
}

// Additional information about the current lifecycle state of the CA bundle.
func (o LookupCaBundleResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// A user-friendly name for the CA bundle. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
func (o LookupCaBundleResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.Name }).(pulumi.StringOutput)
}

// The current lifecycle state of the CA bundle.
func (o LookupCaBundleResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.State }).(pulumi.StringOutput)
}

// A property indicating when the CA bundle was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o LookupCaBundleResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCaBundleResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupCaBundleResultOutput{})
}
