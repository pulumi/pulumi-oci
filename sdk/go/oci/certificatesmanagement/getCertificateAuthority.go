// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package certificatesmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Certificate Authority resource in Oracle Cloud Infrastructure Certificates Management service.
//
// Gets details about the specified certificate authority (CA).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/CertificatesManagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := CertificatesManagement.GetCertificateAuthority(ctx, &certificatesmanagement.GetCertificateAuthorityArgs{
//				CertificateAuthorityId: oci_certificates_management_certificate_authority.Test_certificate_authority.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupCertificateAuthority(ctx *pulumi.Context, args *LookupCertificateAuthorityArgs, opts ...pulumi.InvokeOption) (*LookupCertificateAuthorityResult, error) {
	var rv LookupCertificateAuthorityResult
	err := ctx.Invoke("oci:CertificatesManagement/getCertificateAuthority:getCertificateAuthority", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getCertificateAuthority.
type LookupCertificateAuthorityArgs struct {
	// The OCID of the certificate authority (CA).
	CertificateAuthorityId string `pulumi:"certificateAuthorityId"`
}

// A collection of values returned by getCertificateAuthority.
type LookupCertificateAuthorityResult struct {
	CertificateAuthorityConfigs []GetCertificateAuthorityCertificateAuthorityConfig `pulumi:"certificateAuthorityConfigs"`
	// The OCID of the CA.
	CertificateAuthorityId string `pulumi:"certificateAuthorityId"`
	// An optional list of rules that control how the CA is used and managed.
	CertificateAuthorityRules []GetCertificateAuthorityCertificateAuthorityRule `pulumi:"certificateAuthorityRules"`
	// The details of the certificate revocation list (CRL).
	CertificateRevocationListDetails []GetCertificateAuthorityCertificateRevocationListDetail `pulumi:"certificateRevocationListDetails"`
	// The OCID of the compartment under which the CA is created.
	CompartmentId string `pulumi:"compartmentId"`
	// The origin of the CA.
	ConfigType string `pulumi:"configType"`
	// The metadata details of the certificate authority (CA) version. This summary object does not contain the CA contents.
	CurrentVersions []GetCertificateAuthorityCurrentVersion `pulumi:"currentVersions"`
	// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A brief description of the CA.
	Description string `pulumi:"description"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The OCID of the CA.
	Id string `pulumi:"id"`
	// The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
	IssuerCertificateAuthorityId string `pulumi:"issuerCertificateAuthorityId"`
	// The OCID of the Oracle Cloud Infrastructure Vault key used to encrypt the CA.
	KmsKeyId string `pulumi:"kmsKeyId"`
	// Additional information about the current CA lifecycle state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
	Name string `pulumi:"name"`
	// The algorithm used to sign public key certificates that the CA issues.
	SigningAlgorithm string `pulumi:"signingAlgorithm"`
	// The current lifecycle state of the certificate authority.
	State string `pulumi:"state"`
	// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
	Subjects []GetCertificateAuthoritySubject `pulumi:"subjects"`
	// A property indicating when the CA was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// An optional property indicating when to delete the CA version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
}

func LookupCertificateAuthorityOutput(ctx *pulumi.Context, args LookupCertificateAuthorityOutputArgs, opts ...pulumi.InvokeOption) LookupCertificateAuthorityResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupCertificateAuthorityResult, error) {
			args := v.(LookupCertificateAuthorityArgs)
			r, err := LookupCertificateAuthority(ctx, &args, opts...)
			var s LookupCertificateAuthorityResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupCertificateAuthorityResultOutput)
}

// A collection of arguments for invoking getCertificateAuthority.
type LookupCertificateAuthorityOutputArgs struct {
	// The OCID of the certificate authority (CA).
	CertificateAuthorityId pulumi.StringInput `pulumi:"certificateAuthorityId"`
}

func (LookupCertificateAuthorityOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupCertificateAuthorityArgs)(nil)).Elem()
}

// A collection of values returned by getCertificateAuthority.
type LookupCertificateAuthorityResultOutput struct{ *pulumi.OutputState }

func (LookupCertificateAuthorityResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupCertificateAuthorityResult)(nil)).Elem()
}

func (o LookupCertificateAuthorityResultOutput) ToLookupCertificateAuthorityResultOutput() LookupCertificateAuthorityResultOutput {
	return o
}

func (o LookupCertificateAuthorityResultOutput) ToLookupCertificateAuthorityResultOutputWithContext(ctx context.Context) LookupCertificateAuthorityResultOutput {
	return o
}

func (o LookupCertificateAuthorityResultOutput) CertificateAuthorityConfigs() GetCertificateAuthorityCertificateAuthorityConfigArrayOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) []GetCertificateAuthorityCertificateAuthorityConfig {
		return v.CertificateAuthorityConfigs
	}).(GetCertificateAuthorityCertificateAuthorityConfigArrayOutput)
}

// The OCID of the CA.
func (o LookupCertificateAuthorityResultOutput) CertificateAuthorityId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.CertificateAuthorityId }).(pulumi.StringOutput)
}

// An optional list of rules that control how the CA is used and managed.
func (o LookupCertificateAuthorityResultOutput) CertificateAuthorityRules() GetCertificateAuthorityCertificateAuthorityRuleArrayOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) []GetCertificateAuthorityCertificateAuthorityRule {
		return v.CertificateAuthorityRules
	}).(GetCertificateAuthorityCertificateAuthorityRuleArrayOutput)
}

// The details of the certificate revocation list (CRL).
func (o LookupCertificateAuthorityResultOutput) CertificateRevocationListDetails() GetCertificateAuthorityCertificateRevocationListDetailArrayOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) []GetCertificateAuthorityCertificateRevocationListDetail {
		return v.CertificateRevocationListDetails
	}).(GetCertificateAuthorityCertificateRevocationListDetailArrayOutput)
}

// The OCID of the compartment under which the CA is created.
func (o LookupCertificateAuthorityResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The origin of the CA.
func (o LookupCertificateAuthorityResultOutput) ConfigType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.ConfigType }).(pulumi.StringOutput)
}

// The metadata details of the certificate authority (CA) version. This summary object does not contain the CA contents.
func (o LookupCertificateAuthorityResultOutput) CurrentVersions() GetCertificateAuthorityCurrentVersionArrayOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) []GetCertificateAuthorityCurrentVersion {
		return v.CurrentVersions
	}).(GetCertificateAuthorityCurrentVersionArrayOutput)
}

// Usage of predefined tag keys. These predefined keys are scoped to namespaces. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupCertificateAuthorityResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A brief description of the CA.
func (o LookupCertificateAuthorityResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.Description }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupCertificateAuthorityResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

// The OCID of the CA.
func (o LookupCertificateAuthorityResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the parent CA that issued this CA. If this is the root CA, then this value is null.
func (o LookupCertificateAuthorityResultOutput) IssuerCertificateAuthorityId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.IssuerCertificateAuthorityId }).(pulumi.StringOutput)
}

// The OCID of the Oracle Cloud Infrastructure Vault key used to encrypt the CA.
func (o LookupCertificateAuthorityResultOutput) KmsKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.KmsKeyId }).(pulumi.StringOutput)
}

// Additional information about the current CA lifecycle state.
func (o LookupCertificateAuthorityResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// A user-friendly name for the CA. Names are unique within a compartment. Avoid entering confidential information. Valid characters include uppercase or lowercase letters, numbers, hyphens, underscores, and periods.
func (o LookupCertificateAuthorityResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.Name }).(pulumi.StringOutput)
}

// The algorithm used to sign public key certificates that the CA issues.
func (o LookupCertificateAuthorityResultOutput) SigningAlgorithm() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.SigningAlgorithm }).(pulumi.StringOutput)
}

// The current lifecycle state of the certificate authority.
func (o LookupCertificateAuthorityResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.State }).(pulumi.StringOutput)
}

// The subject of the certificate, which is a distinguished name that identifies the entity that owns the public key in the certificate.
func (o LookupCertificateAuthorityResultOutput) Subjects() GetCertificateAuthoritySubjectArrayOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) []GetCertificateAuthoritySubject { return v.Subjects }).(GetCertificateAuthoritySubjectArrayOutput)
}

// A property indicating when the CA was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o LookupCertificateAuthorityResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// An optional property indicating when to delete the CA version, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: `2019-04-03T21:10:29.600Z`
func (o LookupCertificateAuthorityResultOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v LookupCertificateAuthorityResult) string { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupCertificateAuthorityResultOutput{})
}