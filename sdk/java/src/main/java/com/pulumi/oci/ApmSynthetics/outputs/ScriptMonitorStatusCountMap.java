// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class ScriptMonitorStatusCountMap {
    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    private @Nullable Integer disabled;
    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    private @Nullable Integer enabled;
    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    private @Nullable Integer invalid;
    /**
     * @return Total number of monitors using the script.
     * 
     */
    private @Nullable Integer total;

    private ScriptMonitorStatusCountMap() {}
    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    public Optional<Integer> disabled() {
        return Optional.ofNullable(this.disabled);
    }
    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    public Optional<Integer> enabled() {
        return Optional.ofNullable(this.enabled);
    }
    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    public Optional<Integer> invalid() {
        return Optional.ofNullable(this.invalid);
    }
    /**
     * @return Total number of monitors using the script.
     * 
     */
    public Optional<Integer> total() {
        return Optional.ofNullable(this.total);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ScriptMonitorStatusCountMap defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Integer disabled;
        private @Nullable Integer enabled;
        private @Nullable Integer invalid;
        private @Nullable Integer total;
        public Builder() {}
        public Builder(ScriptMonitorStatusCountMap defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.disabled = defaults.disabled;
    	      this.enabled = defaults.enabled;
    	      this.invalid = defaults.invalid;
    	      this.total = defaults.total;
        }

        @CustomType.Setter
        public Builder disabled(@Nullable Integer disabled) {
            this.disabled = disabled;
            return this;
        }
        @CustomType.Setter
        public Builder enabled(@Nullable Integer enabled) {
            this.enabled = enabled;
            return this;
        }
        @CustomType.Setter
        public Builder invalid(@Nullable Integer invalid) {
            this.invalid = invalid;
            return this;
        }
        @CustomType.Setter
        public Builder total(@Nullable Integer total) {
            this.total = total;
            return this;
        }
        public ScriptMonitorStatusCountMap build() {
            final var o = new ScriptMonitorStatusCountMap();
            o.disabled = disabled;
            o.enabled = enabled;
            o.invalid = invalid;
            o.total = total;
            return o;
        }
    }
}