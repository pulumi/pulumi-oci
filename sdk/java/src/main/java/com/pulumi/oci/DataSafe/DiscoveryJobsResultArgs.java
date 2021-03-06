// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;


public final class DiscoveryJobsResultArgs extends com.pulumi.resources.ResourceArgs {

    public static final DiscoveryJobsResultArgs Empty = new DiscoveryJobsResultArgs();

    @Import(name="discoveryJobId", required=true)
    private Output<String> discoveryJobId;

    public Output<String> discoveryJobId() {
        return this.discoveryJobId;
    }

    private DiscoveryJobsResultArgs() {}

    private DiscoveryJobsResultArgs(DiscoveryJobsResultArgs $) {
        this.discoveryJobId = $.discoveryJobId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DiscoveryJobsResultArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DiscoveryJobsResultArgs $;

        public Builder() {
            $ = new DiscoveryJobsResultArgs();
        }

        public Builder(DiscoveryJobsResultArgs defaults) {
            $ = new DiscoveryJobsResultArgs(Objects.requireNonNull(defaults));
        }

        public Builder discoveryJobId(Output<String> discoveryJobId) {
            $.discoveryJobId = discoveryJobId;
            return this;
        }

        public Builder discoveryJobId(String discoveryJobId) {
            return discoveryJobId(Output.of(discoveryJobId));
        }

        public DiscoveryJobsResultArgs build() {
            $.discoveryJobId = Objects.requireNonNull($.discoveryJobId, "expected parameter 'discoveryJobId' to be non-null");
            return $;
        }
    }

}
