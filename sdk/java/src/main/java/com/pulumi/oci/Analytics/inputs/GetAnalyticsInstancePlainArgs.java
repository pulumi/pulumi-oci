// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Analytics.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetAnalyticsInstancePlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetAnalyticsInstancePlainArgs Empty = new GetAnalyticsInstancePlainArgs();

    /**
     * The OCID of the AnalyticsInstance.
     * 
     */
    @Import(name="analyticsInstanceId", required=true)
    private String analyticsInstanceId;

    /**
     * @return The OCID of the AnalyticsInstance.
     * 
     */
    public String analyticsInstanceId() {
        return this.analyticsInstanceId;
    }

    private GetAnalyticsInstancePlainArgs() {}

    private GetAnalyticsInstancePlainArgs(GetAnalyticsInstancePlainArgs $) {
        this.analyticsInstanceId = $.analyticsInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetAnalyticsInstancePlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetAnalyticsInstancePlainArgs $;

        public Builder() {
            $ = new GetAnalyticsInstancePlainArgs();
        }

        public Builder(GetAnalyticsInstancePlainArgs defaults) {
            $ = new GetAnalyticsInstancePlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param analyticsInstanceId The OCID of the AnalyticsInstance.
         * 
         * @return builder
         * 
         */
        public Builder analyticsInstanceId(String analyticsInstanceId) {
            $.analyticsInstanceId = analyticsInstanceId;
            return this;
        }

        public GetAnalyticsInstancePlainArgs build() {
            $.analyticsInstanceId = Objects.requireNonNull($.analyticsInstanceId, "expected parameter 'analyticsInstanceId' to be non-null");
            return $;
        }
    }

}