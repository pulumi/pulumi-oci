// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Compatible Formats For Data Type resource in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of basic masking formats compatible with the supported data types.
// The data types are grouped into the following categories -
// Character - Includes CHAR, NCHAR, VARCHAR2, and NVARCHAR2
// Numeric - Includes NUMBER, FLOAT, RAW, BINARY_FLOAT, and BINARY_DOUBLE
// Date - Includes DATE and TIMESTAMP
// LOB - Includes BLOB, CLOB, and NCLOB
// All - Includes all the supported data types
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetCompatibleFormatsForDataType(ctx, map[string]interface{}{}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetCompatibleFormatsForDataType(ctx *pulumi.Context, opts ...pulumi.InvokeOption) (*GetCompatibleFormatsForDataTypeResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetCompatibleFormatsForDataTypeResult
	err := ctx.Invoke("oci:DataSafe/getCompatibleFormatsForDataType:getCompatibleFormatsForDataType", nil, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of values returned by getCompatibleFormatsForDataType.
type GetCompatibleFormatsForDataTypeResult struct {
	// An array of lists of basic masking formats compatible with the supported data types.
	FormatsForDataTypes []GetCompatibleFormatsForDataTypeFormatsForDataType `pulumi:"formatsForDataTypes"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
}

func GetCompatibleFormatsForDataTypeOutput(ctx *pulumi.Context, opts ...pulumi.InvokeOption) GetCompatibleFormatsForDataTypeResultOutput {
	return pulumi.ToOutput(0).ApplyT(func(int) (GetCompatibleFormatsForDataTypeResultOutput, error) {
		options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
		return ctx.InvokeOutput("oci:DataSafe/getCompatibleFormatsForDataType:getCompatibleFormatsForDataType", nil, GetCompatibleFormatsForDataTypeResultOutput{}, options).(GetCompatibleFormatsForDataTypeResultOutput), nil
	}).(GetCompatibleFormatsForDataTypeResultOutput)
}

// A collection of values returned by getCompatibleFormatsForDataType.
type GetCompatibleFormatsForDataTypeResultOutput struct{ *pulumi.OutputState }

func (GetCompatibleFormatsForDataTypeResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetCompatibleFormatsForDataTypeResult)(nil)).Elem()
}

func (o GetCompatibleFormatsForDataTypeResultOutput) ToGetCompatibleFormatsForDataTypeResultOutput() GetCompatibleFormatsForDataTypeResultOutput {
	return o
}

func (o GetCompatibleFormatsForDataTypeResultOutput) ToGetCompatibleFormatsForDataTypeResultOutputWithContext(ctx context.Context) GetCompatibleFormatsForDataTypeResultOutput {
	return o
}

// An array of lists of basic masking formats compatible with the supported data types.
func (o GetCompatibleFormatsForDataTypeResultOutput) FormatsForDataTypes() GetCompatibleFormatsForDataTypeFormatsForDataTypeArrayOutput {
	return o.ApplyT(func(v GetCompatibleFormatsForDataTypeResult) []GetCompatibleFormatsForDataTypeFormatsForDataType {
		return v.FormatsForDataTypes
	}).(GetCompatibleFormatsForDataTypeFormatsForDataTypeArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetCompatibleFormatsForDataTypeResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetCompatibleFormatsForDataTypeResult) string { return v.Id }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetCompatibleFormatsForDataTypeResultOutput{})
}
