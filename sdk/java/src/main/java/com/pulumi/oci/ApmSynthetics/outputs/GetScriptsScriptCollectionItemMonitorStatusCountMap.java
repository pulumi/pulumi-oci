// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetScriptsScriptCollectionItemMonitorStatusCountMap {
    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    private final Integer disabled;
    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    private final Integer enabled;
    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    private final Integer invalid;
    /**
     * @return Total number of monitors using the script.
     * 
     */
    private final Integer total;

    @CustomType.Constructor
    private GetScriptsScriptCollectionItemMonitorStatusCountMap(
        @CustomType.Parameter("disabled") Integer disabled,
        @CustomType.Parameter("enabled") Integer enabled,
        @CustomType.Parameter("invalid") Integer invalid,
        @CustomType.Parameter("total") Integer total) {
        this.disabled = disabled;
        this.enabled = enabled;
        this.invalid = invalid;
        this.total = total;
    }

    /**
     * @return Number of disabled monitors using the script.
     * 
     */
    public Integer disabled() {
        return this.disabled;
    }
    /**
     * @return Number of enabled monitors using the script.
     * 
     */
    public Integer enabled() {
        return this.enabled;
    }
    /**
     * @return Number of invalid monitors using the script.
     * 
     */
    public Integer invalid() {
        return this.invalid;
    }
    /**
     * @return Total number of monitors using the script.
     * 
     */
    public Integer total() {
        return this.total;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetScriptsScriptCollectionItemMonitorStatusCountMap defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private Integer disabled;
        private Integer enabled;
        private Integer invalid;
        private Integer total;

        public Builder() {
    	      // Empty
        }

        public Builder(GetScriptsScriptCollectionItemMonitorStatusCountMap defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.disabled = defaults.disabled;
    	      this.enabled = defaults.enabled;
    	      this.invalid = defaults.invalid;
    	      this.total = defaults.total;
        }

        public Builder disabled(Integer disabled) {
            this.disabled = Objects.requireNonNull(disabled);
            return this;
        }
        public Builder enabled(Integer enabled) {
            this.enabled = Objects.requireNonNull(enabled);
            return this;
        }
        public Builder invalid(Integer invalid) {
            this.invalid = Objects.requireNonNull(invalid);
            return this;
        }
        public Builder total(Integer total) {
            this.total = Objects.requireNonNull(total);
            return this;
        }        public GetScriptsScriptCollectionItemMonitorStatusCountMap build() {
            return new GetScriptsScriptCollectionItemMonitorStatusCountMap(disabled, enabled, invalid, total);
        }
    }
}
