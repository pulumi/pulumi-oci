// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package certificatesmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Certificate Authority Versions in Oracle Cloud Infrastructure Certificates Management service.
//
// Lists all versions for the specified certificate authority (CA).
// Optionally, you can use the parameter `FilterByVersionNumberQueryParam` to limit the results to a single item that matches the specified version number.
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
//			_, err := certificatesmanagement.GetCertificateAuthorityVersions(ctx, &certificatesmanagement.GetCertificateAuthorityVersionsArgs{
//				CertificateAuthorityId: testCertificateAuthority.Id,
//				VersionNumber:          pulumi.StringRef(certificateAuthorityVersionVersionNumber),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCertificateAuthorityVersions(ctx *pulumi.Context, args *GetCertificateAuthorityVersionsArgs, opts ...pulumi.InvokeOption) (*GetCertificateAuthorityVersionsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCertificateAuthorityVersionsResult
	err := ctx.Invoke("oci:CertificatesManagement/getCertificateAuthorityVersions:getCertificateAuthorityVersions", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCertificateAuthorityVersions.
type GetCertificateAuthorityVersionsArgs struct {
	// The OCID of the certificate authority (CA).
	CertificateAuthorityId string                                  `pulumi:"certificateAuthorityId"`
	Filters                []GetCertificateAuthorityVersionsFilter `pulumi:"filters"`
	// A filter that returns only resources that match the specified version number. The default value is 0, which means that this filter is not applied.
	VersionNumber *string `pulumi:"versionNumber"`
}

// A collection of values returned by getCertificateAuthorityVersions.
type GetCertificateAuthorityVersionsResult struct {
	// The OCID of the CA.
	CertificateAuthorityId string `pulumi:"certificateAuthorityId"`
	// The list of certificate_authority_version_collection.
	CertificateAuthorityVersionCollections []GetCertificateAuthorityVersionsCertificateAuthorityVersionCollection `pulumi:"certificateAuthorityVersionCollections"`
	Filters                                []GetCertificateAuthorityVersionsFilter                                `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The version number of the CA.
	VersionNumber *string `pulumi:"versionNumber"`
}

func GetCertificateAuthorityVersionsOutput(ctx *pulumi.Context, args GetCertificateAuthorityVersionsOutputArgs, opts ...pulumi.InvokeOption) GetCertificateAuthorityVersionsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetCertificateAuthorityVersionsResultOutput, error) {
			args := v.(GetCertificateAuthorityVersionsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:CertificatesManagement/getCertificateAuthorityVersions:getCertificateAuthorityVersions", args, GetCertificateAuthorityVersionsResultOutput{}, options).(GetCertificateAuthorityVersionsResultOutput), nil
		}).(GetCertificateAuthorityVersionsResultOutput)
}

// A collection of arguments for invoking getCertificateAuthorityVersions.
type GetCertificateAuthorityVersionsOutputArgs struct {
	// The OCID of the certificate authority (CA).
	CertificateAuthorityId pulumi.StringInput                              `pulumi:"certificateAuthorityId"`
	Filters                GetCertificateAuthorityVersionsFilterArrayInput `pulumi:"filters"`
	// A filter that returns only resources that match the specified version number. The default value is 0, which means that this filter is not applied.
	VersionNumber pulumi.StringPtrInput `pulumi:"versionNumber"`
}

func (GetCertificateAuthorityVersionsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCertificateAuthorityVersionsArgs)(nil)).Elem()
}

// A collection of values returned by getCertificateAuthorityVersions.
type GetCertificateAuthorityVersionsResultOutput struct{ *pulumi.OutputState }

func (GetCertificateAuthorityVersionsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCertificateAuthorityVersionsResult)(nil)).Elem()
}

func (o GetCertificateAuthorityVersionsResultOutput) ToGetCertificateAuthorityVersionsResultOutput() GetCertificateAuthorityVersionsResultOutput {
	return o
}

func (o GetCertificateAuthorityVersionsResultOutput) ToGetCertificateAuthorityVersionsResultOutputWithContext(ctx context.Context) GetCertificateAuthorityVersionsResultOutput {
	return o
}

// The OCID of the CA.
func (o GetCertificateAuthorityVersionsResultOutput) CertificateAuthorityId() pulumi.StringOutput {
	return o.ApplyT(func(v GetCertificateAuthorityVersionsResult) string { return v.CertificateAuthorityId }).(pulumi.StringOutput)
}

// The list of certificate_authority_version_collection.
func (o GetCertificateAuthorityVersionsResultOutput) CertificateAuthorityVersionCollections() GetCertificateAuthorityVersionsCertificateAuthorityVersionCollectionArrayOutput {
	return o.ApplyT(func(v GetCertificateAuthorityVersionsResult) []GetCertificateAuthorityVersionsCertificateAuthorityVersionCollection {
		return v.CertificateAuthorityVersionCollections
	}).(GetCertificateAuthorityVersionsCertificateAuthorityVersionCollectionArrayOutput)
}

func (o GetCertificateAuthorityVersionsResultOutput) Filters() GetCertificateAuthorityVersionsFilterArrayOutput {
	return o.ApplyT(func(v GetCertificateAuthorityVersionsResult) []GetCertificateAuthorityVersionsFilter {
		return v.Filters
	}).(GetCertificateAuthorityVersionsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCertificateAuthorityVersionsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCertificateAuthorityVersionsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The version number of the CA.
func (o GetCertificateAuthorityVersionsResultOutput) VersionNumber() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetCertificateAuthorityVersionsResult) *string { return v.VersionNumber }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCertificateAuthorityVersionsResultOutput{})
}
