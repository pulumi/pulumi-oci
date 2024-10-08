// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.MeteringComputation.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;


public final class GetUsageCarbonEmissionsQueryPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetUsageCarbonEmissionsQueryPlainArgs Empty = new GetUsageCarbonEmissionsQueryPlainArgs();

    /**
     * The query unique OCID.
     * 
     */
    @Import(name="usageCarbonEmissionsQueryId", required=true)
    private String usageCarbonEmissionsQueryId;

    /**
     * @return The query unique OCID.
     * 
     */
    public String usageCarbonEmissionsQueryId() {
        return this.usageCarbonEmissionsQueryId;
    }

    private GetUsageCarbonEmissionsQueryPlainArgs() {}

    private GetUsageCarbonEmissionsQueryPlainArgs(GetUsageCarbonEmissionsQueryPlainArgs $) {
        this.usageCarbonEmissionsQueryId = $.usageCarbonEmissionsQueryId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetUsageCarbonEmissionsQueryPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetUsageCarbonEmissionsQueryPlainArgs $;

        public Builder() {
            $ = new GetUsageCarbonEmissionsQueryPlainArgs();
        }

        public Builder(GetUsageCarbonEmissionsQueryPlainArgs defaults) {
            $ = new GetUsageCarbonEmissionsQueryPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param usageCarbonEmissionsQueryId The query unique OCID.
         * 
         * @return builder
         * 
         */
        public Builder usageCarbonEmissionsQueryId(String usageCarbonEmissionsQueryId) {
            $.usageCarbonEmissionsQueryId = usageCarbonEmissionsQueryId;
            return this;
        }

        public GetUsageCarbonEmissionsQueryPlainArgs build() {
            if ($.usageCarbonEmissionsQueryId == null) {
                throw new MissingRequiredPropertyException("GetUsageCarbonEmissionsQueryPlainArgs", "usageCarbonEmissionsQueryId");
            }
            return $;
        }
    }

}
