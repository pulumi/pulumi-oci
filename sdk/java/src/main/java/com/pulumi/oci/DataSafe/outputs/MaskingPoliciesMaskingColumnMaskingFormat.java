// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.MaskingPoliciesMaskingColumnMaskingFormatFormatEntry;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class MaskingPoliciesMaskingColumnMaskingFormat {
    /**
     * @return (Updatable) A condition that must be true for applying the masking format. It can be any valid  SQL construct that can be used in a SQL predicate. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions.
     * 
     */
    private @Nullable String condition;
    /**
     * @return (Updatable) The description of the format entry.
     * 
     */
    private @Nullable String description;
    /**
     * @return (Updatable) An array of format entries. The combined output of all the format entries is  used for masking the column data values.
     * 
     */
    private List<MaskingPoliciesMaskingColumnMaskingFormatFormatEntry> formatEntries;

    private MaskingPoliciesMaskingColumnMaskingFormat() {}
    /**
     * @return (Updatable) A condition that must be true for applying the masking format. It can be any valid  SQL construct that can be used in a SQL predicate. It enables you to do  &lt;a href=&#34;https://docs.oracle.com/en/cloud/paas/data-safe/udscs/conditional-masking.html&#34;&gt;conditional masking&lt;/a&gt;  so that you can mask the column data values differently using different masking  formats and the associated conditions.
     * 
     */
    public Optional<String> condition() {
        return Optional.ofNullable(this.condition);
    }
    /**
     * @return (Updatable) The description of the format entry.
     * 
     */
    public Optional<String> description() {
        return Optional.ofNullable(this.description);
    }
    /**
     * @return (Updatable) An array of format entries. The combined output of all the format entries is  used for masking the column data values.
     * 
     */
    public List<MaskingPoliciesMaskingColumnMaskingFormatFormatEntry> formatEntries() {
        return this.formatEntries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MaskingPoliciesMaskingColumnMaskingFormat defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String condition;
        private @Nullable String description;
        private List<MaskingPoliciesMaskingColumnMaskingFormatFormatEntry> formatEntries;
        public Builder() {}
        public Builder(MaskingPoliciesMaskingColumnMaskingFormat defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.condition = defaults.condition;
    	      this.description = defaults.description;
    	      this.formatEntries = defaults.formatEntries;
        }

        @CustomType.Setter
        public Builder condition(@Nullable String condition) {
            this.condition = condition;
            return this;
        }
        @CustomType.Setter
        public Builder description(@Nullable String description) {
            this.description = description;
            return this;
        }
        @CustomType.Setter
        public Builder formatEntries(List<MaskingPoliciesMaskingColumnMaskingFormatFormatEntry> formatEntries) {
            this.formatEntries = Objects.requireNonNull(formatEntries);
            return this;
        }
        public Builder formatEntries(MaskingPoliciesMaskingColumnMaskingFormatFormatEntry... formatEntries) {
            return formatEntries(List.of(formatEntries));
        }
        public MaskingPoliciesMaskingColumnMaskingFormat build() {
            final var o = new MaskingPoliciesMaskingColumnMaskingFormat();
            o.condition = condition;
            o.description = description;
            o.formatEntries = formatEntries;
            return o;
        }
    }
}