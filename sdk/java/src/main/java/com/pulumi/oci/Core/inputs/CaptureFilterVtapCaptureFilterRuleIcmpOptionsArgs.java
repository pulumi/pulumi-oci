// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs extends com.pulumi.resources.ResourceArgs {

    public static final CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs Empty = new CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs();

    /**
     * (Updatable) The ICMP code (optional).
     * 
     */
    @Import(name="code")
    private @Nullable Output<Integer> code;

    /**
     * @return (Updatable) The ICMP code (optional).
     * 
     */
    public Optional<Output<Integer>> code() {
        return Optional.ofNullable(this.code);
    }

    /**
     * (Updatable) The ICMP type.
     * 
     */
    @Import(name="type", required=true)
    private Output<Integer> type;

    /**
     * @return (Updatable) The ICMP type.
     * 
     */
    public Output<Integer> type() {
        return this.type;
    }

    private CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs() {}

    private CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs(CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs $) {
        this.code = $.code;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs $;

        public Builder() {
            $ = new CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs();
        }

        public Builder(CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs defaults) {
            $ = new CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param code (Updatable) The ICMP code (optional).
         * 
         * @return builder
         * 
         */
        public Builder code(@Nullable Output<Integer> code) {
            $.code = code;
            return this;
        }

        /**
         * @param code (Updatable) The ICMP code (optional).
         * 
         * @return builder
         * 
         */
        public Builder code(Integer code) {
            return code(Output.of(code));
        }

        /**
         * @param type (Updatable) The ICMP type.
         * 
         * @return builder
         * 
         */
        public Builder type(Output<Integer> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The ICMP type.
         * 
         * @return builder
         * 
         */
        public Builder type(Integer type) {
            return type(Output.of(type));
        }

        public CaptureFilterVtapCaptureFilterRuleIcmpOptionsArgs build() {
            $.type = Objects.requireNonNull($.type, "expected parameter 'type' to be non-null");
            return $;
        }
    }

}