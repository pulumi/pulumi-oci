// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Core.inputs.DefaultSecurityListEgressSecurityRuleArgs;
import com.pulumi.oci.Core.inputs.DefaultSecurityListIngressSecurityRuleArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DefaultSecurityListState extends com.pulumi.resources.ResourceArgs {

    public static final DefaultSecurityListState Empty = new DefaultSecurityListState();

    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="egressSecurityRules")
    private @Nullable Output<List<DefaultSecurityListEgressSecurityRuleArgs>> egressSecurityRules;

    public Optional<Output<List<DefaultSecurityListEgressSecurityRuleArgs>>> egressSecurityRules() {
        return Optional.ofNullable(this.egressSecurityRules);
    }

    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    @Import(name="ingressSecurityRules")
    private @Nullable Output<List<DefaultSecurityListIngressSecurityRuleArgs>> ingressSecurityRules;

    public Optional<Output<List<DefaultSecurityListIngressSecurityRuleArgs>>> ingressSecurityRules() {
        return Optional.ofNullable(this.ingressSecurityRules);
    }

    @Import(name="manageDefaultResourceId")
    private @Nullable Output<String> manageDefaultResourceId;

    public Optional<Output<String>> manageDefaultResourceId() {
        return Optional.ofNullable(this.manageDefaultResourceId);
    }

    @Import(name="state")
    private @Nullable Output<String> state;

    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private DefaultSecurityListState() {}

    private DefaultSecurityListState(DefaultSecurityListState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.egressSecurityRules = $.egressSecurityRules;
        this.freeformTags = $.freeformTags;
        this.ingressSecurityRules = $.ingressSecurityRules;
        this.manageDefaultResourceId = $.manageDefaultResourceId;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DefaultSecurityListState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DefaultSecurityListState $;

        public Builder() {
            $ = new DefaultSecurityListState();
        }

        public Builder(DefaultSecurityListState defaults) {
            $ = new DefaultSecurityListState(Objects.requireNonNull(defaults));
        }

        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder egressSecurityRules(@Nullable Output<List<DefaultSecurityListEgressSecurityRuleArgs>> egressSecurityRules) {
            $.egressSecurityRules = egressSecurityRules;
            return this;
        }

        public Builder egressSecurityRules(List<DefaultSecurityListEgressSecurityRuleArgs> egressSecurityRules) {
            return egressSecurityRules(Output.of(egressSecurityRules));
        }

        public Builder egressSecurityRules(DefaultSecurityListEgressSecurityRuleArgs... egressSecurityRules) {
            return egressSecurityRules(List.of(egressSecurityRules));
        }

        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        public Builder ingressSecurityRules(@Nullable Output<List<DefaultSecurityListIngressSecurityRuleArgs>> ingressSecurityRules) {
            $.ingressSecurityRules = ingressSecurityRules;
            return this;
        }

        public Builder ingressSecurityRules(List<DefaultSecurityListIngressSecurityRuleArgs> ingressSecurityRules) {
            return ingressSecurityRules(Output.of(ingressSecurityRules));
        }

        public Builder ingressSecurityRules(DefaultSecurityListIngressSecurityRuleArgs... ingressSecurityRules) {
            return ingressSecurityRules(List.of(ingressSecurityRules));
        }

        public Builder manageDefaultResourceId(@Nullable Output<String> manageDefaultResourceId) {
            $.manageDefaultResourceId = manageDefaultResourceId;
            return this;
        }

        public Builder manageDefaultResourceId(String manageDefaultResourceId) {
            return manageDefaultResourceId(Output.of(manageDefaultResourceId));
        }

        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        public Builder state(String state) {
            return state(Output.of(state));
        }

        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public DefaultSecurityListState build() {
            return $;
        }
    }

}