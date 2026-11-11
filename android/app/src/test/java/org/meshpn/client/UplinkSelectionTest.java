package org.meshpn.client;

import org.junit.Test;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.*;

public class UplinkSelectionTest {
    private static UplinkSelection.Candidate<String> wifi(String id,boolean validated){
        return new UplinkSelection.Candidate<>(id,true,true,false,validated);
    }
    @Test public void vpnDefaultNeverBecomesUplink(){
        assertEquals("wifi",UplinkSelection.choose("vpn",Arrays.asList(
            new UplinkSelection.Candidate<>("vpn",true,false,true,true),wifi("wifi",true))));
    }
    @Test public void contradictoryVpnCapabilitiesAreRejected(){
        assertNull(UplinkSelection.choose("vpn",Arrays.asList(
            new UplinkSelection.Candidate<>("vpn",true,true,true,true),
            new UplinkSelection.Candidate<>("unknown",true,false,false,true))));
    }
    @Test public void validatedCarrierPreferredWhenDefaultIsVpn(){
        assertEquals("ethernet",UplinkSelection.choose("vpn",Arrays.asList(wifi("wifi",false),wifi("ethernet",true))));
    }
    @Test public void physicalSystemDefaultHasPriority(){
        assertEquals("wifi",UplinkSelection.choose("wifi",Arrays.asList(wifi("ethernet",true),wifi("wifi",false))));
    }
    @Test public void unvalidatedPhysicalInternetStillAllowsTryingExit(){
        assertEquals("hotspot",UplinkSelection.choose("vpn",Arrays.asList(wifi("hotspot",false))));
    }
    @Test public void noPhysicalInternetHasNoDefaultFallback(){
        assertNull(UplinkSelection.choose("vpn",Collections.emptyList()));
        assertNull(UplinkSelection.choose("local",Arrays.asList(new UplinkSelection.Candidate<>("local",false,true,false,true))));
    }
    @Test public void newAttemptSelectsNewCarrierAfterLoss(){
        assertEquals("wifi-old",UplinkSelection.choose("vpn",Arrays.asList(wifi("wifi-old",true))));
        assertEquals("wifi-new",UplinkSelection.choose("vpn",Arrays.asList(wifi("wifi-new",true))));
        assertNull(UplinkSelection.choose("wifi-old",Collections.emptyList()));
    }
}
