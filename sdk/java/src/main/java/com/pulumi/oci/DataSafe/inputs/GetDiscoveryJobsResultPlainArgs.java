// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class GetDiscoveryJobsResultPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDiscoveryJobsResultPlainArgs Empty = new GetDiscoveryJobsResultPlainArgs();

    /**
     * The OCID of the discovery job.
     * 
     */
    @Import(name="discoveryJobId", required=true)
    private String discoveryJobId;

    /**
     * @return The OCID of the discovery job.
     * 
     */
    public String discoveryJobId() {
        return this.discoveryJobId;
    }

    /**
     * The unique key that identifies the discovery result.
     * 
     */
    @Import(name="resultKey", required=true)
    private String resultKey;

    /**
     * @return The unique key that identifies the discovery result.
     * 
     */
    public String resultKey() {
        return this.resultKey;
    }

    private GetDiscoveryJobsResultPlainArgs() {}

    private GetDiscoveryJobsResultPlainArgs(GetDiscoveryJobsResultPlainArgs $) {
        this.discoveryJobId = $.discoveryJobId;
        this.resultKey = $.resultKey;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDiscoveryJobsResultPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDiscoveryJobsResultPlainArgs $;

        public Builder() {
            $ = new GetDiscoveryJobsResultPlainArgs();
        }

        public Builder(GetDiscoveryJobsResultPlainArgs defaults) {
            $ = new GetDiscoveryJobsResultPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param discoveryJobId The OCID of the discovery job.
         * 
         * @return builder
         * 
         */
        public Builder discoveryJobId(String discoveryJobId) {
            $.discoveryJobId = discoveryJobId;
            return this;
        }

        /**
         * @param resultKey The unique key that identifies the discovery result.
         * 
         * @return builder
         * 
         */
        public Builder resultKey(String resultKey) {
            $.resultKey = resultKey;
            return this;
        }

        public GetDiscoveryJobsResultPlainArgs build() {
            $.discoveryJobId = Objects.requireNonNull($.discoveryJobId, "expected parameter 'discoveryJobId' to be non-null");
            $.resultKey = Objects.requireNonNull($.resultKey, "expected parameter 'resultKey' to be non-null");
            return $;
        }
    }

}