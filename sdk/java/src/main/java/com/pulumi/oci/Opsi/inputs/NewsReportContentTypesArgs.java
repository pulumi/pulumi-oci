// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.List;
import java.util.Objects;


public final class NewsReportContentTypesArgs extends com.pulumi.resources.ResourceArgs {

    public static final NewsReportContentTypesArgs Empty = new NewsReportContentTypesArgs();

    /**
     * (Updatable) Supported resources for capacity planning content type.
     * 
     */
    @Import(name="capacityPlanningResources", required=true)
    private Output<List<String>> capacityPlanningResources;

    /**
     * @return (Updatable) Supported resources for capacity planning content type.
     * 
     */
    public Output<List<String>> capacityPlanningResources() {
        return this.capacityPlanningResources;
    }

    private NewsReportContentTypesArgs() {}

    private NewsReportContentTypesArgs(NewsReportContentTypesArgs $) {
        this.capacityPlanningResources = $.capacityPlanningResources;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NewsReportContentTypesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NewsReportContentTypesArgs $;

        public Builder() {
            $ = new NewsReportContentTypesArgs();
        }

        public Builder(NewsReportContentTypesArgs defaults) {
            $ = new NewsReportContentTypesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param capacityPlanningResources (Updatable) Supported resources for capacity planning content type.
         * 
         * @return builder
         * 
         */
        public Builder capacityPlanningResources(Output<List<String>> capacityPlanningResources) {
            $.capacityPlanningResources = capacityPlanningResources;
            return this;
        }

        /**
         * @param capacityPlanningResources (Updatable) Supported resources for capacity planning content type.
         * 
         * @return builder
         * 
         */
        public Builder capacityPlanningResources(List<String> capacityPlanningResources) {
            return capacityPlanningResources(Output.of(capacityPlanningResources));
        }

        /**
         * @param capacityPlanningResources (Updatable) Supported resources for capacity planning content type.
         * 
         * @return builder
         * 
         */
        public Builder capacityPlanningResources(String... capacityPlanningResources) {
            return capacityPlanningResources(List.of(capacityPlanningResources));
        }

        public NewsReportContentTypesArgs build() {
            $.capacityPlanningResources = Objects.requireNonNull($.capacityPlanningResources, "expected parameter 'capacityPlanningResources' to be non-null");
            return $;
        }
    }

}