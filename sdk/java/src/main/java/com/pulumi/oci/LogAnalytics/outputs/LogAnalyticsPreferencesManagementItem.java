// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.LogAnalytics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class LogAnalyticsPreferencesManagementItem {
    /**
     * @return The preference name. Currently, only &#34;DEFAULT_HOMEPAGE&#34; is supported.
     * 
     */
    private @Nullable String name;
    /**
     * @return The preference value.
     * 
     */
    private @Nullable String value;

    private LogAnalyticsPreferencesManagementItem() {}
    /**
     * @return The preference name. Currently, only &#34;DEFAULT_HOMEPAGE&#34; is supported.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return The preference value.
     * 
     */
    public Optional<String> value() {
        return Optional.ofNullable(this.value);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(LogAnalyticsPreferencesManagementItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String name;
        private @Nullable String value;
        public Builder() {}
        public Builder(LogAnalyticsPreferencesManagementItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.name = defaults.name;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder value(@Nullable String value) {
            this.value = value;
            return this;
        }
        public LogAnalyticsPreferencesManagementItem build() {
            final var o = new LogAnalyticsPreferencesManagementItem();
            o.name = name;
            o.value = value;
            return o;
        }
    }
}