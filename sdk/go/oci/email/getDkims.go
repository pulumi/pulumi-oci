// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package email

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Dkims in Oracle Cloud Infrastructure Email service.
//
// Lists DKIMs for an email domain.
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
//			_, err := email.GetDkims(ctx, &email.GetDkimsArgs{
//				EmailDomainId: testEmailDomain.Id,
//				Id:            pulumi.StringRef(dkimId),
//				Name:          pulumi.StringRef(dkimName),
//				State:         pulumi.StringRef(dkimState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetDkims(ctx *pulumi.Context, args *GetDkimsArgs, opts ...pulumi.InvokeOption) (*GetDkimsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetDkimsResult
	err := ctx.Invoke("oci:Email/getDkims:getDkims", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDkims.
type GetDkimsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
	EmailDomainId string           `pulumi:"emailDomainId"`
	Filters       []GetDkimsFilter `pulumi:"filters"`
	// A filter to only return resources that match the given id exactly.
	Id *string `pulumi:"id"`
	// A filter to only return resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// Filter returned list by specified lifecycle state. This parameter is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getDkims.
type GetDkimsResult struct {
	// The list of dkim_collection.
	DkimCollections []GetDkimsDkimCollection `pulumi:"dkimCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
	EmailDomainId string           `pulumi:"emailDomainId"`
	Filters       []GetDkimsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
	Id *string `pulumi:"id"`
	// The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
	Name *string `pulumi:"name"`
	// The current state of the DKIM.
	State *string `pulumi:"state"`
}

func GetDkimsOutput(ctx *pulumi.Context, args GetDkimsOutputArgs, opts ...pulumi.InvokeOption) GetDkimsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetDkimsResultOutput, error) {
			args := v.(GetDkimsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Email/getDkims:getDkims", args, GetDkimsResultOutput{}, options).(GetDkimsResultOutput), nil
		}).(GetDkimsResultOutput)
}

// A collection of arguments for invoking getDkims.
type GetDkimsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain to which this DKIM belongs.
	EmailDomainId pulumi.StringInput       `pulumi:"emailDomainId"`
	Filters       GetDkimsFilterArrayInput `pulumi:"filters"`
	// A filter to only return resources that match the given id exactly.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to only return resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// Filter returned list by specified lifecycle state. This parameter is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetDkimsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDkimsArgs)(nil)).Elem()
}

// A collection of values returned by getDkims.
type GetDkimsResultOutput struct{ *pulumi.OutputState }

func (GetDkimsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetDkimsResult)(nil)).Elem()
}

func (o GetDkimsResultOutput) ToGetDkimsResultOutput() GetDkimsResultOutput {
	return o
}

func (o GetDkimsResultOutput) ToGetDkimsResultOutputWithContext(ctx context.Context) GetDkimsResultOutput {
	return o
}

// The list of dkim_collection.
func (o GetDkimsResultOutput) DkimCollections() GetDkimsDkimCollectionArrayOutput {
	return o.ApplyT(func(v GetDkimsResult) []GetDkimsDkimCollection { return v.DkimCollections }).(GetDkimsDkimCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the email domain that this DKIM belongs to.
func (o GetDkimsResultOutput) EmailDomainId() pulumi.StringOutput {
	return o.ApplyT(func(v GetDkimsResult) string { return v.EmailDomainId }).(pulumi.StringOutput)
}

func (o GetDkimsResultOutput) Filters() GetDkimsFilterArrayOutput {
	return o.ApplyT(func(v GetDkimsResult) []GetDkimsFilter { return v.Filters }).(GetDkimsFilterArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DKIM.
func (o GetDkimsResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDkimsResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The DKIM selector. If the same domain is managed in more than one region, each region must use different selectors.
func (o GetDkimsResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDkimsResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The current state of the DKIM.
func (o GetDkimsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetDkimsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetDkimsResultOutput{})
}
