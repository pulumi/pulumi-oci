// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package recoverymod

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Protected Database Fetch Configuration resource in Oracle Cloud Infrastructure Recovery service.
//
// Downloads the network service configuration file 'tnsnames.ora' for a specified protected database. Applies to user-defined recovery systems only.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/recoverymod"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := recoverymod.GetProtectedDatabaseFetchConfiguration(ctx, &recoverymod.GetProtectedDatabaseFetchConfigurationArgs{
//				ProtectedDatabaseId: testProtectedDatabase.Id,
//				Base64EncodeContent: pulumi.BoolRef(true),
//				ConfigurationType:   pulumi.StringRef(protectedDatabaseFetchConfigurationConfigurationType),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetProtectedDatabaseFetchConfiguration(ctx *pulumi.Context, args *GetProtectedDatabaseFetchConfigurationArgs, opts ...pulumi.InvokeOption) (*GetProtectedDatabaseFetchConfigurationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetProtectedDatabaseFetchConfigurationResult
	err := ctx.Invoke("oci:RecoveryMod/getProtectedDatabaseFetchConfiguration:getProtectedDatabaseFetchConfiguration", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getProtectedDatabaseFetchConfiguration.
type GetProtectedDatabaseFetchConfigurationArgs struct {
	Base64EncodeContent *bool `pulumi:"base64EncodeContent"`
	// Currently has four config options ALL, TNSNAMES, HOSTS and CABUNDLE. All will return a zipped folder containing the contents of both tnsnames and the certificateChainPem.
	ConfigurationType *string `pulumi:"configurationType"`
	// The protected database OCID.
	ProtectedDatabaseId string `pulumi:"protectedDatabaseId"`
}

// A collection of values returned by getProtectedDatabaseFetchConfiguration.
type GetProtectedDatabaseFetchConfigurationResult struct {
	Base64EncodeContent *bool   `pulumi:"base64EncodeContent"`
	ConfigurationType   *string `pulumi:"configurationType"`
	// content of the downloaded config file for recovery service. It is base64 encoded by default. To store the config in plaintext set `base64EncodeContent` to false.
	Content string `pulumi:"content"`
	// The provider-assigned unique ID for this managed resource.
	Id                  string `pulumi:"id"`
	ProtectedDatabaseId string `pulumi:"protectedDatabaseId"`
}

func GetProtectedDatabaseFetchConfigurationOutput(ctx *pulumi.Context, args GetProtectedDatabaseFetchConfigurationOutputArgs, opts ...pulumi.InvokeOption) GetProtectedDatabaseFetchConfigurationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetProtectedDatabaseFetchConfigurationResultOutput, error) {
			args := v.(GetProtectedDatabaseFetchConfigurationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:RecoveryMod/getProtectedDatabaseFetchConfiguration:getProtectedDatabaseFetchConfiguration", args, GetProtectedDatabaseFetchConfigurationResultOutput{}, options).(GetProtectedDatabaseFetchConfigurationResultOutput), nil
		}).(GetProtectedDatabaseFetchConfigurationResultOutput)
}

// A collection of arguments for invoking getProtectedDatabaseFetchConfiguration.
type GetProtectedDatabaseFetchConfigurationOutputArgs struct {
	Base64EncodeContent pulumi.BoolPtrInput `pulumi:"base64EncodeContent"`
	// Currently has four config options ALL, TNSNAMES, HOSTS and CABUNDLE. All will return a zipped folder containing the contents of both tnsnames and the certificateChainPem.
	ConfigurationType pulumi.StringPtrInput `pulumi:"configurationType"`
	// The protected database OCID.
	ProtectedDatabaseId pulumi.StringInput `pulumi:"protectedDatabaseId"`
}

func (GetProtectedDatabaseFetchConfigurationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProtectedDatabaseFetchConfigurationArgs)(nil)).Elem()
}

// A collection of values returned by getProtectedDatabaseFetchConfiguration.
type GetProtectedDatabaseFetchConfigurationResultOutput struct{ *pulumi.OutputState }

func (GetProtectedDatabaseFetchConfigurationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetProtectedDatabaseFetchConfigurationResult)(nil)).Elem()
}

func (o GetProtectedDatabaseFetchConfigurationResultOutput) ToGetProtectedDatabaseFetchConfigurationResultOutput() GetProtectedDatabaseFetchConfigurationResultOutput {
	return o
}

func (o GetProtectedDatabaseFetchConfigurationResultOutput) ToGetProtectedDatabaseFetchConfigurationResultOutputWithContext(ctx context.Context) GetProtectedDatabaseFetchConfigurationResultOutput {
	return o
}

func (o GetProtectedDatabaseFetchConfigurationResultOutput) Base64EncodeContent() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetProtectedDatabaseFetchConfigurationResult) *bool { return v.Base64EncodeContent }).(pulumi.BoolPtrOutput)
}

func (o GetProtectedDatabaseFetchConfigurationResultOutput) ConfigurationType() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetProtectedDatabaseFetchConfigurationResult) *string { return v.ConfigurationType }).(pulumi.StringPtrOutput)
}

// content of the downloaded config file for recovery service. It is base64 encoded by default. To store the config in plaintext set `base64EncodeContent` to false.
func (o GetProtectedDatabaseFetchConfigurationResultOutput) Content() pulumi.StringOutput {
	return o.ApplyT(func(v GetProtectedDatabaseFetchConfigurationResult) string { return v.Content }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetProtectedDatabaseFetchConfigurationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetProtectedDatabaseFetchConfigurationResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetProtectedDatabaseFetchConfigurationResultOutput) ProtectedDatabaseId() pulumi.StringOutput {
	return o.ApplyT(func(v GetProtectedDatabaseFetchConfigurationResult) string { return v.ProtectedDatabaseId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetProtectedDatabaseFetchConfigurationResultOutput{})
}
