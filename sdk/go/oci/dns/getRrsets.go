// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of RRsets in Oracle Cloud Infrastructure DNS service.
//
// Gets a list of all rrsets in the specified zone.
//
// You can optionally filter the results using the listed parameters. When the zone name
// is provided as a path parameter and `PRIVATE` is used for the scope query parameter then
// the viewId parameter is required.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dns.GetRrsets(ctx, &dns.GetRrsetsArgs{
//				ZoneNameOrId:   testZone.Id,
//				Domain:         pulumi.StringRef(rrsetDomain),
//				DomainContains: pulumi.StringRef(rrsetDomain),
//				Rtype:          pulumi.StringRef(rrsetRtype),
//				Scope:          pulumi.StringRef(rrsetScope),
//				ViewId:         pulumi.StringRef(testView.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetRrsets(ctx *pulumi.Context, args *GetRrsetsArgs, opts ...pulumi.InvokeOption) (*GetRrsetsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetRrsetsResult
	err := ctx.Invoke("oci:Dns/getRrsets:getRrsets", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRrsets.
type GetRrsetsArgs struct {
	// The target fully-qualified domain name (FQDN) within the target zone.
	Domain *string `pulumi:"domain"`
	// Matches any rrset whose fully-qualified domain name (FQDN) contains the provided value.
	DomainContains *string           `pulumi:"domainContains"`
	Filters        []GetRrsetsFilter `pulumi:"filters"`
	// Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
	Rtype *string `pulumi:"rtype"`
	// Specifies to operate only on resources that have a matching DNS scope.
	Scope *string `pulumi:"scope"`
	// The OCID of the view the zone is associated with. Required when accessing a private zone by name.
	ViewId *string `pulumi:"viewId"`
	// The name or OCID of the target zone.
	ZoneNameOrId string `pulumi:"zoneNameOrId"`
}

// A collection of values returned by getRrsets.
type GetRrsetsResult struct {
	// The fully qualified domain name where the record can be located.
	Domain         *string           `pulumi:"domain"`
	DomainContains *string           `pulumi:"domainContains"`
	Filters        []GetRrsetsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of rrsets.
	Rrsets []GetRrsetsRrset `pulumi:"rrsets"`
	// The type of DNS record, such as A or CNAME. For more information, see [Resource Record (RR) TYPEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4).
	Rtype        *string `pulumi:"rtype"`
	Scope        *string `pulumi:"scope"`
	ViewId       *string `pulumi:"viewId"`
	ZoneNameOrId string  `pulumi:"zoneNameOrId"`
}

func GetRrsetsOutput(ctx *pulumi.Context, args GetRrsetsOutputArgs, opts ...pulumi.InvokeOption) GetRrsetsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetRrsetsResultOutput, error) {
			args := v.(GetRrsetsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Dns/getRrsets:getRrsets", args, GetRrsetsResultOutput{}, options).(GetRrsetsResultOutput), nil
		}).(GetRrsetsResultOutput)
}

// A collection of arguments for invoking getRrsets.
type GetRrsetsOutputArgs struct {
	// The target fully-qualified domain name (FQDN) within the target zone.
	Domain pulumi.StringPtrInput `pulumi:"domain"`
	// Matches any rrset whose fully-qualified domain name (FQDN) contains the provided value.
	DomainContains pulumi.StringPtrInput     `pulumi:"domainContains"`
	Filters        GetRrsetsFilterArrayInput `pulumi:"filters"`
	// Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
	Rtype pulumi.StringPtrInput `pulumi:"rtype"`
	// Specifies to operate only on resources that have a matching DNS scope.
	Scope pulumi.StringPtrInput `pulumi:"scope"`
	// The OCID of the view the zone is associated with. Required when accessing a private zone by name.
	ViewId pulumi.StringPtrInput `pulumi:"viewId"`
	// The name or OCID of the target zone.
	ZoneNameOrId pulumi.StringInput `pulumi:"zoneNameOrId"`
}

func (GetRrsetsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRrsetsArgs)(nil)).Elem()
}

// A collection of values returned by getRrsets.
type GetRrsetsResultOutput struct{ *pulumi.OutputState }

func (GetRrsetsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetRrsetsResult)(nil)).Elem()
}

func (o GetRrsetsResultOutput) ToGetRrsetsResultOutput() GetRrsetsResultOutput {
	return o
}

func (o GetRrsetsResultOutput) ToGetRrsetsResultOutputWithContext(ctx context.Context) GetRrsetsResultOutput {
	return o
}

// The fully qualified domain name where the record can be located.
func (o GetRrsetsResultOutput) Domain() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRrsetsResult) *string { return v.Domain }).(pulumi.StringPtrOutput)
}

func (o GetRrsetsResultOutput) DomainContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRrsetsResult) *string { return v.DomainContains }).(pulumi.StringPtrOutput)
}

func (o GetRrsetsResultOutput) Filters() GetRrsetsFilterArrayOutput {
	return o.ApplyT(func(v GetRrsetsResult) []GetRrsetsFilter { return v.Filters }).(GetRrsetsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetRrsetsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetRrsetsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of rrsets.
func (o GetRrsetsResultOutput) Rrsets() GetRrsetsRrsetArrayOutput {
	return o.ApplyT(func(v GetRrsetsResult) []GetRrsetsRrset { return v.Rrsets }).(GetRrsetsRrsetArrayOutput)
}

// The type of DNS record, such as A or CNAME. For more information, see [Resource Record (RR) TYPEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4).
func (o GetRrsetsResultOutput) Rtype() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRrsetsResult) *string { return v.Rtype }).(pulumi.StringPtrOutput)
}

func (o GetRrsetsResultOutput) Scope() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRrsetsResult) *string { return v.Scope }).(pulumi.StringPtrOutput)
}

func (o GetRrsetsResultOutput) ViewId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetRrsetsResult) *string { return v.ViewId }).(pulumi.StringPtrOutput)
}

func (o GetRrsetsResultOutput) ZoneNameOrId() pulumi.StringOutput {
	return o.ApplyT(func(v GetRrsetsResult) string { return v.ZoneNameOrId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetRrsetsResultOutput{})
}
