// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetObjectLifecyclePolicyRuleObjectNameFilter {
    /**
     * @return An array of glob patterns to match the object names to exclude. An empty array is ignored. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     */
    private List<String> exclusionPatterns;
    /**
     * @return An array of glob patterns to match the object names to include. An empty array includes all objects in the bucket. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     */
    private List<String> inclusionPatterns;
    /**
     * @return An array of object name prefixes that the rule will apply to. An empty array means to include all objects.
     * 
     */
    private List<String> inclusionPrefixes;

    private GetObjectLifecyclePolicyRuleObjectNameFilter() {}
    /**
     * @return An array of glob patterns to match the object names to exclude. An empty array is ignored. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     */
    public List<String> exclusionPatterns() {
        return this.exclusionPatterns;
    }
    /**
     * @return An array of glob patterns to match the object names to include. An empty array includes all objects in the bucket. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     */
    public List<String> inclusionPatterns() {
        return this.inclusionPatterns;
    }
    /**
     * @return An array of object name prefixes that the rule will apply to. An empty array means to include all objects.
     * 
     */
    public List<String> inclusionPrefixes() {
        return this.inclusionPrefixes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetObjectLifecyclePolicyRuleObjectNameFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> exclusionPatterns;
        private List<String> inclusionPatterns;
        private List<String> inclusionPrefixes;
        public Builder() {}
        public Builder(GetObjectLifecyclePolicyRuleObjectNameFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.exclusionPatterns = defaults.exclusionPatterns;
    	      this.inclusionPatterns = defaults.inclusionPatterns;
    	      this.inclusionPrefixes = defaults.inclusionPrefixes;
        }

        @CustomType.Setter
        public Builder exclusionPatterns(List<String> exclusionPatterns) {
            this.exclusionPatterns = Objects.requireNonNull(exclusionPatterns);
            return this;
        }
        public Builder exclusionPatterns(String... exclusionPatterns) {
            return exclusionPatterns(List.of(exclusionPatterns));
        }
        @CustomType.Setter
        public Builder inclusionPatterns(List<String> inclusionPatterns) {
            this.inclusionPatterns = Objects.requireNonNull(inclusionPatterns);
            return this;
        }
        public Builder inclusionPatterns(String... inclusionPatterns) {
            return inclusionPatterns(List.of(inclusionPatterns));
        }
        @CustomType.Setter
        public Builder inclusionPrefixes(List<String> inclusionPrefixes) {
            this.inclusionPrefixes = Objects.requireNonNull(inclusionPrefixes);
            return this;
        }
        public Builder inclusionPrefixes(String... inclusionPrefixes) {
            return inclusionPrefixes(List.of(inclusionPrefixes));
        }
        public GetObjectLifecyclePolicyRuleObjectNameFilter build() {
            final var o = new GetObjectLifecyclePolicyRuleObjectNameFilter();
            o.exclusionPatterns = exclusionPatterns;
            o.inclusionPatterns = inclusionPatterns;
            o.inclusionPrefixes = inclusionPrefixes;
            return o;
        }
    }
}