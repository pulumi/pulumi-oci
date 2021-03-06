// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainReplicaRegion {
    /**
     * @return A REPLICATION_ENABLED region, e.g. us-ashburn-1. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.
     * 
     */
    private final @Nullable String region;
    /**
     * @return The current state.
     * 
     */
    private final @Nullable String state;
    /**
     * @return Region agnostic domain URL.
     * 
     */
    private final @Nullable String url;

    @CustomType.Constructor
    private DomainReplicaRegion(
        @CustomType.Parameter("region") @Nullable String region,
        @CustomType.Parameter("state") @Nullable String state,
        @CustomType.Parameter("url") @Nullable String url) {
        this.region = region;
        this.state = state;
        this.url = url;
    }

    /**
     * @return A REPLICATION_ENABLED region, e.g. us-ashburn-1. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.
     * 
     */
    public Optional<String> region() {
        return Optional.ofNullable(this.region);
    }
    /**
     * @return The current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return Region agnostic domain URL.
     * 
     */
    public Optional<String> url() {
        return Optional.ofNullable(this.url);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainReplicaRegion defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String region;
        private @Nullable String state;
        private @Nullable String url;

        public Builder() {
    	      // Empty
        }

        public Builder(DomainReplicaRegion defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.region = defaults.region;
    	      this.state = defaults.state;
    	      this.url = defaults.url;
        }

        public Builder region(@Nullable String region) {
            this.region = region;
            return this;
        }
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        public Builder url(@Nullable String url) {
            this.url = url;
            return this;
        }        public DomainReplicaRegion build() {
            return new DomainReplicaRegion(region, state, url);
        }
    }
}
