// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package fleetappsmanagement

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Announcements in Oracle Cloud Infrastructure Fleet Apps Management service.
//
// Return a list of Announcement Summary items in a tenancy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/fleetappsmanagement"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := fleetappsmanagement.GetAnnouncements(ctx, &fleetappsmanagement.GetAnnouncementsArgs{
//				CompartmentId:   compartmentId,
//				DisplayName:     pulumi.StringRef(announcementDisplayName),
//				SummaryContains: pulumi.StringRef(announcementSummaryContains),
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
	err := ctx.Invoke("oci:FleetAppsManagement/getAnnouncements:getAnnouncements", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getAnnouncements.
type GetAnnouncementsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetAnnouncementsFilter `pulumi:"filters"`
	// Filter the list of announcements that contains the given summary value.
	SummaryContains *string `pulumi:"summaryContains"`
}

// A collection of values returned by getAnnouncements.
type GetAnnouncementsResult struct {
	// The list of announcement_collection.
	AnnouncementCollections []GetAnnouncementsAnnouncementCollection `pulumi:"announcementCollections"`
	// Tenancy OCID
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetAnnouncementsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id              string  `pulumi:"id"`
	SummaryContains *string `pulumi:"summaryContains"`
}

func GetAnnouncementsOutput(ctx *pulumi.Context, args GetAnnouncementsOutputArgs, opts ...pulumi.InvokeOption) GetAnnouncementsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetAnnouncementsResultOutput, error) {
			args := v.(GetAnnouncementsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:FleetAppsManagement/getAnnouncements:getAnnouncements", args, GetAnnouncementsResultOutput{}, options).(GetAnnouncementsResultOutput), nil
		}).(GetAnnouncementsResultOutput)
}

// A collection of arguments for invoking getAnnouncements.
type GetAnnouncementsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetAnnouncementsFilterArrayInput `pulumi:"filters"`
	// Filter the list of announcements that contains the given summary value.
	SummaryContains pulumi.StringPtrInput `pulumi:"summaryContains"`
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

// Tenancy OCID
func (o GetAnnouncementsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o GetAnnouncementsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetAnnouncementsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
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

func init() {
	pulumi.RegisterOutputType(GetAnnouncementsResultOutput{})
}
