// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ObjectStorage.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class ObjectLifecyclePolicyRuleObjectNameFilter {
    /**
     * @return (Updatable) An array of glob patterns to match the object names to exclude. An empty array is ignored. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     * The special pattern characters have the following meanings:
     * 
     * \           Escapes the following character
     * *           Matches any string of characters. ?           Matches any single character . [...]       Matches a group of characters. A group of characters can be: A set of characters, for example: [Zafg9{@literal @}]. This matches any character in the brackets. A range of characters, for example: [a-z]. This matches any character in the range. [a-f] is equivalent to [abcdef]. For character ranges only the CHARACTER-CHARACTER pattern is supported. [ab-yz] is not valid [a-mn-z] is not valid Character ranges can not start with ^ or : To include a &#39;-&#39; in the range, make it the first or last character.
     * 
     */
    private @Nullable List<String> exclusionPatterns;
    /**
     * @return (Updatable) An array of glob patterns to match the object names to include. An empty array includes all objects in the bucket. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     * The special pattern characters have the following meanings:
     * 
     * \           Escapes the following character
     * *           Matches any string of characters. ?           Matches any single character . [...]       Matches a group of characters. A group of characters can be: A set of characters, for example: [Zafg9{@literal @}]. This matches any character in the brackets. A range of characters, for example: [a-z]. This matches any character in the range. [a-f] is equivalent to [abcdef]. For character ranges only the CHARACTER-CHARACTER pattern is supported. [ab-yz] is not valid [a-mn-z] is not valid Character ranges can not start with ^ or : To include a &#39;-&#39; in the range, make it the first or last character.
     * 
     */
    private @Nullable List<String> inclusionPatterns;
    /**
     * @return (Updatable) An array of object name prefixes that the rule will apply to. An empty array means to include all objects.
     * 
     */
    private @Nullable List<String> inclusionPrefixes;

    private ObjectLifecyclePolicyRuleObjectNameFilter() {}
    /**
     * @return (Updatable) An array of glob patterns to match the object names to exclude. An empty array is ignored. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     * The special pattern characters have the following meanings:
     * 
     * \           Escapes the following character
     * *           Matches any string of characters. ?           Matches any single character . [...]       Matches a group of characters. A group of characters can be: A set of characters, for example: [Zafg9{@literal @}]. This matches any character in the brackets. A range of characters, for example: [a-z]. This matches any character in the range. [a-f] is equivalent to [abcdef]. For character ranges only the CHARACTER-CHARACTER pattern is supported. [ab-yz] is not valid [a-mn-z] is not valid Character ranges can not start with ^ or : To include a &#39;-&#39; in the range, make it the first or last character.
     * 
     */
    public List<String> exclusionPatterns() {
        return this.exclusionPatterns == null ? List.of() : this.exclusionPatterns;
    }
    /**
     * @return (Updatable) An array of glob patterns to match the object names to include. An empty array includes all objects in the bucket. Exclusion patterns take precedence over inclusion patterns. A Glob pattern is a sequence of characters to match text. Any character that appears in the pattern, other than the special pattern characters described below, matches itself. Glob patterns must be between 1 and 1024 characters.
     * 
     * The special pattern characters have the following meanings:
     * 
     * \           Escapes the following character
     * *           Matches any string of characters. ?           Matches any single character . [...]       Matches a group of characters. A group of characters can be: A set of characters, for example: [Zafg9{@literal @}]. This matches any character in the brackets. A range of characters, for example: [a-z]. This matches any character in the range. [a-f] is equivalent to [abcdef]. For character ranges only the CHARACTER-CHARACTER pattern is supported. [ab-yz] is not valid [a-mn-z] is not valid Character ranges can not start with ^ or : To include a &#39;-&#39; in the range, make it the first or last character.
     * 
     */
    public List<String> inclusionPatterns() {
        return this.inclusionPatterns == null ? List.of() : this.inclusionPatterns;
    }
    /**
     * @return (Updatable) An array of object name prefixes that the rule will apply to. An empty array means to include all objects.
     * 
     */
    public List<String> inclusionPrefixes() {
        return this.inclusionPrefixes == null ? List.of() : this.inclusionPrefixes;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ObjectLifecyclePolicyRuleObjectNameFilter defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable List<String> exclusionPatterns;
        private @Nullable List<String> inclusionPatterns;
        private @Nullable List<String> inclusionPrefixes;
        public Builder() {}
        public Builder(ObjectLifecyclePolicyRuleObjectNameFilter defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.exclusionPatterns = defaults.exclusionPatterns;
    	      this.inclusionPatterns = defaults.inclusionPatterns;
    	      this.inclusionPrefixes = defaults.inclusionPrefixes;
        }

        @CustomType.Setter
        public Builder exclusionPatterns(@Nullable List<String> exclusionPatterns) {

            this.exclusionPatterns = exclusionPatterns;
            return this;
        }
        public Builder exclusionPatterns(String... exclusionPatterns) {
            return exclusionPatterns(List.of(exclusionPatterns));
        }
        @CustomType.Setter
        public Builder inclusionPatterns(@Nullable List<String> inclusionPatterns) {

            this.inclusionPatterns = inclusionPatterns;
            return this;
        }
        public Builder inclusionPatterns(String... inclusionPatterns) {
            return inclusionPatterns(List.of(inclusionPatterns));
        }
        @CustomType.Setter
        public Builder inclusionPrefixes(@Nullable List<String> inclusionPrefixes) {

            this.inclusionPrefixes = inclusionPrefixes;
            return this;
        }
        public Builder inclusionPrefixes(String... inclusionPrefixes) {
            return inclusionPrefixes(List.of(inclusionPrefixes));
        }
        public ObjectLifecyclePolicyRuleObjectNameFilter build() {
            final var _resultValue = new ObjectLifecyclePolicyRuleObjectNameFilter();
            _resultValue.exclusionPatterns = exclusionPatterns;
            _resultValue.inclusionPatterns = inclusionPatterns;
            _resultValue.inclusionPrefixes = inclusionPrefixes;
            return _resultValue;
        }
    }
}
