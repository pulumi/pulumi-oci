// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package managementagent

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Management Agent Data Sources in Oracle Cloud Infrastructure Management Agent service.
//
// A list of Management Agent Data Sources for the given Management Agent Id.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/managementagent"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := managementagent.GetManagementAgentDataSources(ctx, &managementagent.GetManagementAgentDataSourcesArgs{
//				ManagementAgentId: testManagementAgent.Id,
//				Name:              pulumi.StringRef(managementAgentDataSourceName),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetManagementAgentDataSources(ctx *pulumi.Context, args *GetManagementAgentDataSourcesArgs, opts ...pulumi.InvokeOption) (*GetManagementAgentDataSourcesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetManagementAgentDataSourcesResult
	err := ctx.Invoke("oci:ManagementAgent/getManagementAgentDataSources:getManagementAgentDataSources", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getManagementAgentDataSources.
type GetManagementAgentDataSourcesArgs struct {
	Filters []GetManagementAgentDataSourcesFilter `pulumi:"filters"`
	// Unique Management Agent identifier
	ManagementAgentId string `pulumi:"managementAgentId"`
	// Unique name of the dataSource.
	Name *string `pulumi:"name"`
}

// A collection of values returned by getManagementAgentDataSources.
type GetManagementAgentDataSourcesResult struct {
	// The list of data_sources.
	DataSources []GetManagementAgentDataSourcesDataSource `pulumi:"dataSources"`
	Filters     []GetManagementAgentDataSourcesFilter     `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                string `pulumi:"id"`
	ManagementAgentId string `pulumi:"managementAgentId"`
	// Unique name of the DataSource.
	Name *string `pulumi:"name"`
}

func GetManagementAgentDataSourcesOutput(ctx *pulumi.Context, args GetManagementAgentDataSourcesOutputArgs, opts ...pulumi.InvokeOption) GetManagementAgentDataSourcesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetManagementAgentDataSourcesResultOutput, error) {
			args := v.(GetManagementAgentDataSourcesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ManagementAgent/getManagementAgentDataSources:getManagementAgentDataSources", args, GetManagementAgentDataSourcesResultOutput{}, options).(GetManagementAgentDataSourcesResultOutput), nil
		}).(GetManagementAgentDataSourcesResultOutput)
}

// A collection of arguments for invoking getManagementAgentDataSources.
type GetManagementAgentDataSourcesOutputArgs struct {
	Filters GetManagementAgentDataSourcesFilterArrayInput `pulumi:"filters"`
	// Unique Management Agent identifier
	ManagementAgentId pulumi.StringInput `pulumi:"managementAgentId"`
	// Unique name of the dataSource.
	Name pulumi.StringPtrInput `pulumi:"name"`
}

func (GetManagementAgentDataSourcesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementAgentDataSourcesArgs)(nil)).Elem()
}

// A collection of values returned by getManagementAgentDataSources.
type GetManagementAgentDataSourcesResultOutput struct{ *pulumi.OutputState }

func (GetManagementAgentDataSourcesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetManagementAgentDataSourcesResult)(nil)).Elem()
}

func (o GetManagementAgentDataSourcesResultOutput) ToGetManagementAgentDataSourcesResultOutput() GetManagementAgentDataSourcesResultOutput {
	return o
}

func (o GetManagementAgentDataSourcesResultOutput) ToGetManagementAgentDataSourcesResultOutputWithContext(ctx context.Context) GetManagementAgentDataSourcesResultOutput {
	return o
}

// The list of data_sources.
func (o GetManagementAgentDataSourcesResultOutput) DataSources() GetManagementAgentDataSourcesDataSourceArrayOutput {
	return o.ApplyT(func(v GetManagementAgentDataSourcesResult) []GetManagementAgentDataSourcesDataSource {
		return v.DataSources
	}).(GetManagementAgentDataSourcesDataSourceArrayOutput)
}

func (o GetManagementAgentDataSourcesResultOutput) Filters() GetManagementAgentDataSourcesFilterArrayOutput {
	return o.ApplyT(func(v GetManagementAgentDataSourcesResult) []GetManagementAgentDataSourcesFilter { return v.Filters }).(GetManagementAgentDataSourcesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetManagementAgentDataSourcesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagementAgentDataSourcesResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetManagementAgentDataSourcesResultOutput) ManagementAgentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetManagementAgentDataSourcesResult) string { return v.ManagementAgentId }).(pulumi.StringOutput)
}

// Unique name of the DataSource.
func (o GetManagementAgentDataSourcesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetManagementAgentDataSourcesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetManagementAgentDataSourcesResultOutput{})
}
