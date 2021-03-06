// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class TriggerActionFilterInclude {
    /**
     * @return (Updatable) The target branch for pull requests; not applicable for push requests.
     * 
     */
    private final @Nullable String baseRef;
    /**
     * @return (Updatable) Branch for push event; source branch for pull requests.
     * 
     */
    private final @Nullable String headRef;

    @CustomType.Constructor
    private TriggerActionFilterInclude(
        @CustomType.Parameter("baseRef") @Nullable String baseRef,
        @CustomType.Parameter("headRef") @Nullable String headRef) {
        this.baseRef = baseRef;
        this.headRef = headRef;
    }

    /**
     * @return (Updatable) The target branch for pull requests; not applicable for push requests.
     * 
     */
    public Optional<String> baseRef() {
        return Optional.ofNullable(this.baseRef);
    }
    /**
     * @return (Updatable) Branch for push event; source branch for pull requests.
     * 
     */
    public Optional<String> headRef() {
        return Optional.ofNullable(this.headRef);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(TriggerActionFilterInclude defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String baseRef;
        private @Nullable String headRef;

        public Builder() {
    	      // Empty
        }

        public Builder(TriggerActionFilterInclude defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.baseRef = defaults.baseRef;
    	      this.headRef = defaults.headRef;
        }

        public Builder baseRef(@Nullable String baseRef) {
            this.baseRef = baseRef;
            return this;
        }
        public Builder headRef(@Nullable String headRef) {
            this.headRef = headRef;
            return this;
        }        public TriggerActionFilterInclude build() {
            return new TriggerActionFilterInclude(baseRef, headRef);
        }
    }
}
