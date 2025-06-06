// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DataSafeConfigurationGlobalSetting {
    /**
     * @return The paid usage option chosen by the customer admin.
     * 
     */
    private @Nullable Boolean isPaidUsage;
    /**
     * @return The offline retention period in months.
     * 
     */
    private @Nullable Integer offlineRetentionPeriod;
    /**
     * @return The online retention period in months.
     * 
     */
    private @Nullable Integer onlineRetentionPeriod;

    private DataSafeConfigurationGlobalSetting() {}
    /**
     * @return The paid usage option chosen by the customer admin.
     * 
     */
    public Optional<Boolean> isPaidUsage() {
        return Optional.ofNullable(this.isPaidUsage);
    }
    /**
     * @return The offline retention period in months.
     * 
     */
    public Optional<Integer> offlineRetentionPeriod() {
        return Optional.ofNullable(this.offlineRetentionPeriod);
    }
    /**
     * @return The online retention period in months.
     * 
     */
    public Optional<Integer> onlineRetentionPeriod() {
        return Optional.ofNullable(this.onlineRetentionPeriod);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DataSafeConfigurationGlobalSetting defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean isPaidUsage;
        private @Nullable Integer offlineRetentionPeriod;
        private @Nullable Integer onlineRetentionPeriod;
        public Builder() {}
        public Builder(DataSafeConfigurationGlobalSetting defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.isPaidUsage = defaults.isPaidUsage;
    	      this.offlineRetentionPeriod = defaults.offlineRetentionPeriod;
    	      this.onlineRetentionPeriod = defaults.onlineRetentionPeriod;
        }

        @CustomType.Setter
        public Builder isPaidUsage(@Nullable Boolean isPaidUsage) {

            this.isPaidUsage = isPaidUsage;
            return this;
        }
        @CustomType.Setter
        public Builder offlineRetentionPeriod(@Nullable Integer offlineRetentionPeriod) {

            this.offlineRetentionPeriod = offlineRetentionPeriod;
            return this;
        }
        @CustomType.Setter
        public Builder onlineRetentionPeriod(@Nullable Integer onlineRetentionPeriod) {

            this.onlineRetentionPeriod = onlineRetentionPeriod;
            return this;
        }
        public DataSafeConfigurationGlobalSetting build() {
            final var _resultValue = new DataSafeConfigurationGlobalSetting();
            _resultValue.isPaidUsage = isPaidUsage;
            _resultValue.offlineRetentionPeriod = offlineRetentionPeriod;
            _resultValue.onlineRetentionPeriod = onlineRetentionPeriod;
            return _resultValue;
        }
    }
}
