// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Announcements in Oracle Cloud Infrastructure Jms service.
//
// # Return a list of AnnouncementSummary items
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/jms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := jms.GetAnnouncements(ctx, &jms.GetAnnouncementsArgs{
//				SummaryContains: pulumi.StringRef(announcementSummaryContains),
//				TimeEnd:         pulumi.StringRef(announcementTimeEnd),
//				TimeStart:       pulumi.StringRef(announcementTimeStart),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetAnnouncements(ctx *pulumi.Context, args *GetAnnouncementsArgs, opts ...pulumi.InvokeOption) (*GetAnnouncementsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetAnnouncementsResult
	err := ctx.Invoke("oci:Jms/getAnnouncements:getAnnouncements", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAnnouncements.
type GetAnnouncementsArgs struct {
	Filters []GetAnnouncementsFilter `pulumi:"filters"`
	// Filter the list with summary contains the given value.
	SummaryContains *string `pulumi:"summaryContains"`
	// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd *string `pulumi:"timeEnd"`
	// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart *string `pulumi:"timeStart"`
}

// A collection of values returned by getAnnouncements.
type GetAnnouncementsResult struct {
	// The list of announcement_collection.
	AnnouncementCollections []GetAnnouncementsAnnouncementCollection `pulumi:"announcementCollections"`
	Filters                 []GetAnnouncementsFilter                 `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id              string  `pulumi:"id"`
	SummaryContains *string `pulumi:"summaryContains"`
	TimeEnd         *string `pulumi:"timeEnd"`
	TimeStart       *string `pulumi:"timeStart"`
}

func GetAnnouncementsOutput(ctx *pulumi.Context, args GetAnnouncementsOutputArgs, opts ...pulumi.InvokeOption) GetAnnouncementsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAnnouncementsResultOutput, error) {
			args := v.(GetAnnouncementsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getAnnouncements:getAnnouncements", args, GetAnnouncementsResultOutput{}, options).(GetAnnouncementsResultOutput), nil
		}).(GetAnnouncementsResultOutput)
}

// A collection of arguments for invoking getAnnouncements.
type GetAnnouncementsOutputArgs struct {
	Filters GetAnnouncementsFilterArrayInput `pulumi:"filters"`
	// Filter the list with summary contains the given value.
	SummaryContains pulumi.StringPtrInput `pulumi:"summaryContains"`
	// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd pulumi.StringPtrInput `pulumi:"timeEnd"`
	// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart pulumi.StringPtrInput `pulumi:"timeStart"`
}

func (GetAnnouncementsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAnnouncementsArgs)(nil)).Elem()
}

// A collection of values returned by getAnnouncements.
type GetAnnouncementsResultOutput struct{ *pulumi.OutputState }

func (GetAnnouncementsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetAnnouncementsResult)(nil)).Elem()
}

func (o GetAnnouncementsResultOutput) ToGetAnnouncementsResultOutput() GetAnnouncementsResultOutput {
	return o
}

func (o GetAnnouncementsResultOutput) ToGetAnnouncementsResultOutputWithContext(ctx context.Context) GetAnnouncementsResultOutput {
	return o
}

// The list of announcement_collection.
func (o GetAnnouncementsResultOutput) AnnouncementCollections() GetAnnouncementsAnnouncementCollectionArrayOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) []GetAnnouncementsAnnouncementCollection {
		return v.AnnouncementCollections
	}).(GetAnnouncementsAnnouncementCollectionArrayOutput)
}

func (o GetAnnouncementsResultOutput) Filters() GetAnnouncementsFilterArrayOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) []GetAnnouncementsFilter { return v.Filters }).(GetAnnouncementsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetAnnouncementsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetAnnouncementsResultOutput) SummaryContains() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) *string { return v.SummaryContains }).(pulumi.StringPtrOutput)
}

func (o GetAnnouncementsResultOutput) TimeEnd() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) *string { return v.TimeEnd }).(pulumi.StringPtrOutput)
}

func (o GetAnnouncementsResultOutput) TimeStart() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) *string { return v.TimeStart }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetAnnouncementsResultOutput{})
}
