// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Oracle Db Azure Blob Mount resource in Oracle Cloud Infrastructure Dbmulticloud service.
//
// Get Oracle DB Azure Blob Mount Details form a particular Container Resource ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/oci"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := oci.LookupDbmulticloudOracleDbAzureBlobMount(ctx, &oci.LookupDbmulticloudOracleDbAzureBlobMountArgs{
//				OracleDbAzureBlobMountId: testOracleDbAzureBlobMountOciDbmulticloudOracleDbAzureBlobMount.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupDbmulticloudOracleDbAzureBlobMount(ctx *pulumi.Context, args *LookupDbmulticloudOracleDbAzureBlobMountArgs, opts ...pulumi.InvokeOption) (*LookupDbmulticloudOracleDbAzureBlobMountResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupDbmulticloudOracleDbAzureBlobMountResult
	err := ctx.Invoke("oci:oci/getDbmulticloudOracleDbAzureBlobMount:getDbmulticloudOracleDbAzureBlobMount", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getDbmulticloudOracleDbAzureBlobMount.
type LookupDbmulticloudOracleDbAzureBlobMountArgs struct {
	// The ID of the Azure Container Resource.
	OracleDbAzureBlobMountId string `pulumi:"oracleDbAzureBlobMountId"`
}

// A collection of values returned by getDbmulticloudOracleDbAzureBlobMount.
type LookupDbmulticloudOracleDbAzureBlobMountResult struct {
	// The OCID of the compartment that contains Oracle DB Azure Blob Mount resource.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Oracle DB Azure Blob Mount name.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID for the new Oracle DB Azure Blob Mount resource.
	Id string `pulumi:"id"`
	// Description of the latest modification of the Oracle DB Azure Blob Mount Resource.
	LastModification string `pulumi:"lastModification"`
	// Description of the current lifecycle state in more detail.
	LifecycleStateDetails string `pulumi:"lifecycleStateDetails"`
	// Azure Container mount path.
	MountPath string `pulumi:"mountPath"`
	// The OCID of the Oracle DB Azure Blob Container Resource.
	OracleDbAzureBlobContainerId string `pulumi:"oracleDbAzureBlobContainerId"`
	OracleDbAzureBlobMountId     string `pulumi:"oracleDbAzureBlobMountId"`
	// The OCID of the Oracle DB Azure Connector Resource.
	OracleDbAzureConnectorId string `pulumi:"oracleDbAzureConnectorId"`
	// The current lifecycle state of the Azure Arc Agent Resource.
	State string `pulumi:"state"`
	// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// Time when the Oracle DB Azure Blob Mount was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
	TimeCreated string `pulumi:"timeCreated"`
	// Time when the Oracle DB Azure Blob Mount was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupDbmulticloudOracleDbAzureBlobMountOutput(ctx *pulumi.Context, args LookupDbmulticloudOracleDbAzureBlobMountOutputArgs, opts ...pulumi.InvokeOption) LookupDbmulticloudOracleDbAzureBlobMountResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupDbmulticloudOracleDbAzureBlobMountResultOutput, error) {
			args := v.(LookupDbmulticloudOracleDbAzureBlobMountArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:oci/getDbmulticloudOracleDbAzureBlobMount:getDbmulticloudOracleDbAzureBlobMount", args, LookupDbmulticloudOracleDbAzureBlobMountResultOutput{}, options).(LookupDbmulticloudOracleDbAzureBlobMountResultOutput), nil
		}).(LookupDbmulticloudOracleDbAzureBlobMountResultOutput)
}

// A collection of arguments for invoking getDbmulticloudOracleDbAzureBlobMount.
type LookupDbmulticloudOracleDbAzureBlobMountOutputArgs struct {
	// The ID of the Azure Container Resource.
	OracleDbAzureBlobMountId pulumi.StringInput `pulumi:"oracleDbAzureBlobMountId"`
}

func (LookupDbmulticloudOracleDbAzureBlobMountOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDbmulticloudOracleDbAzureBlobMountArgs)(nil)).Elem()
}

// A collection of values returned by getDbmulticloudOracleDbAzureBlobMount.
type LookupDbmulticloudOracleDbAzureBlobMountResultOutput struct{ *pulumi.OutputState }

func (LookupDbmulticloudOracleDbAzureBlobMountResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupDbmulticloudOracleDbAzureBlobMountResult)(nil)).Elem()
}

func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) ToLookupDbmulticloudOracleDbAzureBlobMountResultOutput() LookupDbmulticloudOracleDbAzureBlobMountResultOutput {
	return o
}

func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) ToLookupDbmulticloudOracleDbAzureBlobMountResultOutputWithContext(ctx context.Context) LookupDbmulticloudOracleDbAzureBlobMountResultOutput {
	return o
}

// The OCID of the compartment that contains Oracle DB Azure Blob Mount resource.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Oracle DB Azure Blob Mount name.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID for the new Oracle DB Azure Blob Mount resource.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.Id }).(pulumi.StringOutput)
}

// Description of the latest modification of the Oracle DB Azure Blob Mount Resource.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) LastModification() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.LastModification }).(pulumi.StringOutput)
}

// Description of the current lifecycle state in more detail.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) LifecycleStateDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.LifecycleStateDetails }).(pulumi.StringOutput)
}

// Azure Container mount path.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) MountPath() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.MountPath }).(pulumi.StringOutput)
}

// The OCID of the Oracle DB Azure Blob Container Resource.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) OracleDbAzureBlobContainerId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.OracleDbAzureBlobContainerId }).(pulumi.StringOutput)
}

func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) OracleDbAzureBlobMountId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.OracleDbAzureBlobMountId }).(pulumi.StringOutput)
}

// The OCID of the Oracle DB Azure Connector Resource.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) OracleDbAzureConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.OracleDbAzureConnectorId }).(pulumi.StringOutput)
}

// The current lifecycle state of the Azure Arc Agent Resource.
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// Time when the Oracle DB Azure Blob Mount was created in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// Time when the Oracle DB Azure Blob Mount was last modified, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format, e.g. '2020-05-22T21:10:29.600Z'
func (o LookupDbmulticloudOracleDbAzureBlobMountResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupDbmulticloudOracleDbAzureBlobMountResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupDbmulticloudOracleDbAzureBlobMountResultOutput{})
}
