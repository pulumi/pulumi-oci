// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package goldengate

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Deployment Certificate resource in Oracle Cloud Infrastructure Golden Gate service.
//
// Retrieves a Certificate.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/goldengate"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := goldengate.GetDeploymentCertificate(ctx, &goldengate.GetDeploymentCertificateArgs{
//				CertificateKey: deploymentCertificateCertificateKey,
//				DeploymentId:   testDeployment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDeploymentCertificate(ctx *pulumi.Context, args *LookupDeploymentCertificateArgs, opts ...pulumi.InvokeOption) (*LookupDeploymentCertificateResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDeploymentCertificateResult
	err := ctx.Invoke("oci:GoldenGate/getDeploymentCertificate:getDeploymentCertificate", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDeploymentCertificate.
type LookupDeploymentCertificateArgs struct {
	// A unique certificate identifier.
	CertificateKey string `pulumi:"certificateKey"`
	// A unique Deployment identifier.
	DeploymentId string `pulumi:"deploymentId"`
}

// A collection of values returned by getDeploymentCertificate.
type LookupDeploymentCertificateResult struct {
	// The Certificate authority key id.
	AuthorityKeyId string `pulumi:"authorityKeyId"`
	// The base64 encoded content of the PEM file containing the SSL certificate.
	CertificateContent string `pulumi:"certificateContent"`
	CertificateKey     string `pulumi:"certificateKey"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
	DeploymentId string `pulumi:"deploymentId"`
	Id           string `pulumi:"id"`
	// Indicates if the certificate is ca.
	IsCa           bool `pulumi:"isCa"`
	IsLockOverride bool `pulumi:"isLockOverride"`
	// Indicates if the certificate is self signed.
	IsSelfSigned bool `pulumi:"isSelfSigned"`
	// The Certificate issuer.
	Issuer string `pulumi:"issuer"`
	// The identifier key (unique name in the scope of the deployment) of the certificate being referenced.  It must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
	Key string `pulumi:"key"`
	// The Certificate md5Hash.
	Md5hash string `pulumi:"md5hash"`
	// The Certificate public key.
	PublicKey string `pulumi:"publicKey"`
	// The Certificate public key algorithm.
	PublicKeyAlgorithm string `pulumi:"publicKeyAlgorithm"`
	// The Certificate public key size.
	PublicKeySize string `pulumi:"publicKeySize"`
	// The Certificate serial.
	Serial string `pulumi:"serial"`
	// The Certificate sha1 hash.
	Sha1hash string `pulumi:"sha1hash"`
	// Possible certificate lifecycle states.
	State string `pulumi:"state"`
	// The Certificate subject.
	Subject string `pulumi:"subject"`
	// The Certificate subject key id.
	SubjectKeyId string `pulumi:"subjectKeyId"`
	// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeCreated string `pulumi:"timeCreated"`
	// The time the certificate is valid from. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeValidFrom string `pulumi:"timeValidFrom"`
	// The time the certificate is valid to. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
	TimeValidTo string `pulumi:"timeValidTo"`
	// The Certificate version.
	Version string `pulumi:"version"`
}

func LookupDeploymentCertificateOutput(ctx *pulumi.Context, args LookupDeploymentCertificateOutputArgs, opts ...pulumi.InvokeOption) LookupDeploymentCertificateResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDeploymentCertificateResultOutput, error) {
			args := v.(LookupDeploymentCertificateArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:GoldenGate/getDeploymentCertificate:getDeploymentCertificate", args, LookupDeploymentCertificateResultOutput{}, options).(LookupDeploymentCertificateResultOutput), nil
		}).(LookupDeploymentCertificateResultOutput)
}

// A collection of arguments for invoking getDeploymentCertificate.
type LookupDeploymentCertificateOutputArgs struct {
	// A unique certificate identifier.
	CertificateKey pulumi.StringInput `pulumi:"certificateKey"`
	// A unique Deployment identifier.
	DeploymentId pulumi.StringInput `pulumi:"deploymentId"`
}

func (LookupDeploymentCertificateOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDeploymentCertificateArgs)(nil)).Elem()
}

// A collection of values returned by getDeploymentCertificate.
type LookupDeploymentCertificateResultOutput struct{ *pulumi.OutputState }

func (LookupDeploymentCertificateResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDeploymentCertificateResult)(nil)).Elem()
}

func (o LookupDeploymentCertificateResultOutput) ToLookupDeploymentCertificateResultOutput() LookupDeploymentCertificateResultOutput {
	return o
}

func (o LookupDeploymentCertificateResultOutput) ToLookupDeploymentCertificateResultOutputWithContext(ctx context.Context) LookupDeploymentCertificateResultOutput {
	return o
}

// The Certificate authority key id.
func (o LookupDeploymentCertificateResultOutput) AuthorityKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.AuthorityKeyId }).(pulumi.StringOutput)
}

// The base64 encoded content of the PEM file containing the SSL certificate.
func (o LookupDeploymentCertificateResultOutput) CertificateContent() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.CertificateContent }).(pulumi.StringOutput)
}

func (o LookupDeploymentCertificateResultOutput) CertificateKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.CertificateKey }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the deployment being referenced.
func (o LookupDeploymentCertificateResultOutput) DeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.DeploymentId }).(pulumi.StringOutput)
}

func (o LookupDeploymentCertificateResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Id }).(pulumi.StringOutput)
}

// Indicates if the certificate is ca.
func (o LookupDeploymentCertificateResultOutput) IsCa() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) bool { return v.IsCa }).(pulumi.BoolOutput)
}

func (o LookupDeploymentCertificateResultOutput) IsLockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) bool { return v.IsLockOverride }).(pulumi.BoolOutput)
}

// Indicates if the certificate is self signed.
func (o LookupDeploymentCertificateResultOutput) IsSelfSigned() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) bool { return v.IsSelfSigned }).(pulumi.BoolOutput)
}

// The Certificate issuer.
func (o LookupDeploymentCertificateResultOutput) Issuer() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Issuer }).(pulumi.StringOutput)
}

// The identifier key (unique name in the scope of the deployment) of the certificate being referenced.  It must be 1 to 32 characters long, must contain only alphanumeric characters and must start with a letter.
func (o LookupDeploymentCertificateResultOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Key }).(pulumi.StringOutput)
}

// The Certificate md5Hash.
func (o LookupDeploymentCertificateResultOutput) Md5hash() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Md5hash }).(pulumi.StringOutput)
}

// The Certificate public key.
func (o LookupDeploymentCertificateResultOutput) PublicKey() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.PublicKey }).(pulumi.StringOutput)
}

// The Certificate public key algorithm.
func (o LookupDeploymentCertificateResultOutput) PublicKeyAlgorithm() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.PublicKeyAlgorithm }).(pulumi.StringOutput)
}

// The Certificate public key size.
func (o LookupDeploymentCertificateResultOutput) PublicKeySize() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.PublicKeySize }).(pulumi.StringOutput)
}

// The Certificate serial.
func (o LookupDeploymentCertificateResultOutput) Serial() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Serial }).(pulumi.StringOutput)
}

// The Certificate sha1 hash.
func (o LookupDeploymentCertificateResultOutput) Sha1hash() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Sha1hash }).(pulumi.StringOutput)
}

// Possible certificate lifecycle states.
func (o LookupDeploymentCertificateResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.State }).(pulumi.StringOutput)
}

// The Certificate subject.
func (o LookupDeploymentCertificateResultOutput) Subject() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Subject }).(pulumi.StringOutput)
}

// The Certificate subject key id.
func (o LookupDeploymentCertificateResultOutput) SubjectKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.SubjectKeyId }).(pulumi.StringOutput)
}

// The time the resource was created. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o LookupDeploymentCertificateResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the certificate is valid from. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o LookupDeploymentCertificateResultOutput) TimeValidFrom() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.TimeValidFrom }).(pulumi.StringOutput)
}

// The time the certificate is valid to. The format is defined by [RFC3339](https://tools.ietf.org/html/rfc3339), such as `2016-08-25T21:10:29.600Z`.
func (o LookupDeploymentCertificateResultOutput) TimeValidTo() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.TimeValidTo }).(pulumi.StringOutput)
}

// The Certificate version.
func (o LookupDeploymentCertificateResultOutput) Version() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDeploymentCertificateResult) string { return v.Version }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDeploymentCertificateResultOutput{})
}
