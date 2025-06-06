// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package email

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Email Return Paths in Oracle Cloud Infrastructure Email service.
//
// Lists email return paths in the specified compartment or emaildomain.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/email"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := email.GetEmailReturnPaths(ctx, &email.GetEmailReturnPathsArgs{
//				CompartmentId:    pulumi.StringRef(compartmentId),
//				Id:               pulumi.StringRef(emailReturnPathId),
//				Name:             pulumi.StringRef(emailReturnPathName),
//				ParentResourceId: pulumi.StringRef(testResource.Id),
//				State:            pulumi.StringRef(emailReturnPathState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetEmailReturnPaths(ctx *pulumi.Context, args *GetEmailReturnPathsArgs, opts ...pulumi.InvokeOption) (*GetEmailReturnPathsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetEmailReturnPathsResult
	err := ctx.Invoke("oci:Email/getEmailReturnPaths:getEmailReturnPaths", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getEmailReturnPaths.
type GetEmailReturnPathsArgs struct {
	// The OCID for the compartment.
	CompartmentId *string                     `pulumi:"compartmentId"`
	Filters       []GetEmailReturnPathsFilter `pulumi:"filters"`
	// A filter to only return resources that match the given id exactly.
	Id *string `pulumi:"id"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Email Domain to which this Email Return Path belongs.
	ParentResourceId *string `pulumi:"parentResourceId"`
	// Filter returned list by specified lifecycle state. This parameter is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getEmailReturnPaths.
type GetEmailReturnPathsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this email return path.
	CompartmentId *string `pulumi:"compartmentId"`
	// The list of email_return_path_collection.
	EmailReturnPathCollections []GetEmailReturnPathsEmailReturnPathCollection `pulumi:"emailReturnPathCollections"`
	Filters                    []GetEmailReturnPathsFilter                    `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email return path.
	Id *string `pulumi:"id"`
	// The email return path domain in the Internet Domain Name System (DNS).  Example: `iad1.rp.example.com`
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the EmailDomain that this email return path belongs to.
	ParentResourceId *string `pulumi:"parentResourceId"`
	// The current state of the email return path.
	State *string `pulumi:"state"`
}

func GetEmailReturnPathsOutput(ctx *pulumi.Context, args GetEmailReturnPathsOutputArgs, opts ...pulumi.InvokeOption) GetEmailReturnPathsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetEmailReturnPathsResultOutput, error) {
			args := v.(GetEmailReturnPathsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Email/getEmailReturnPaths:getEmailReturnPaths", args, GetEmailReturnPathsResultOutput{}, options).(GetEmailReturnPathsResultOutput), nil
		}).(GetEmailReturnPathsResultOutput)
}

// A collection of arguments for invoking getEmailReturnPaths.
type GetEmailReturnPathsOutputArgs struct {
	// The OCID for the compartment.
	CompartmentId pulumi.StringPtrInput               `pulumi:"compartmentId"`
	Filters       GetEmailReturnPathsFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given id exactly.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Email Domain to which this Email Return Path belongs.
	ParentResourceId pulumi.StringPtrInput `pulumi:"parentResourceId"`
	// Filter returned list by specified lifecycle state. This parameter is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetEmailReturnPathsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetEmailReturnPathsArgs)(nil)).Elem()
}

// A collection of values returned by getEmailReturnPaths.
type GetEmailReturnPathsResultOutput struct{ *pulumi.OutputState }

func (GetEmailReturnPathsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetEmailReturnPathsResult)(nil)).Elem()
}

func (o GetEmailReturnPathsResultOutput) ToGetEmailReturnPathsResultOutput() GetEmailReturnPathsResultOutput {
	return o
}

func (o GetEmailReturnPathsResultOutput) ToGetEmailReturnPathsResultOutputWithContext(ctx context.Context) GetEmailReturnPathsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains this email return path.
func (o GetEmailReturnPathsResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The list of email_return_path_collection.
func (o GetEmailReturnPathsResultOutput) EmailReturnPathCollections() GetEmailReturnPathsEmailReturnPathCollectionArrayOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) []GetEmailReturnPathsEmailReturnPathCollection {
		return v.EmailReturnPathCollections
	}).(GetEmailReturnPathsEmailReturnPathCollectionArrayOutput)
}

func (o GetEmailReturnPathsResultOutput) Filters() GetEmailReturnPathsFilterArrayOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) []GetEmailReturnPathsFilter { return v.Filters }).(GetEmailReturnPathsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email return path.
func (o GetEmailReturnPathsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The email return path domain in the Internet Domain Name System (DNS).  Example: `iad1.rp.example.com`
func (o GetEmailReturnPathsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the EmailDomain that this email return path belongs to.
func (o GetEmailReturnPathsResultOutput) ParentResourceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) *string { return v.ParentResourceId }).(pulumi.StringPtrOutput)
}

// The current state of the email return path.
func (o GetEmailReturnPathsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetEmailReturnPathsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetEmailReturnPathsResultOutput{})
}
