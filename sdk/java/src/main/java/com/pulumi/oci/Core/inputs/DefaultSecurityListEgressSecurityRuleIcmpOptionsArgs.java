// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs Empty = new DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs();

    @Import(name="code")
    private @Nullable Output<Integer> code;

    public Optional<Output<Integer>> code() {
        return Optional.ofNullable(this.code);
    }

    @Import(name="type", required=true)
    private Output<Integer> type;

    public Output<Integer> type() {
        return this.type;
    }

    private DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs() {}

    private DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs(DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs $) {
        this.code = $.code;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs $;

        public Builder() {
            $ = new DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs();
        }

        public Builder(DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs defaults) {
            $ = new DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs(Objects.requireNonNull(defaults));
        }

        public Builder code(@Nullable Output<Integer> code) {
            $.code = code;
            return this;
        }

        public Builder code(Integer code) {
            return code(Output.of(code));
        }

        public Builder type(Output<Integer> type) {
            $.type = type;
            return this;
        }

        public Builder type(Integer type) {
            return type(Output.of(type));
        }

        public DefaultSecurityListEgressSecurityRuleIcmpOptionsArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}