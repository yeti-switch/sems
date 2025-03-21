/*
 *  Copyright (c) 2011 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */


/*
 * This file contains the function WebRtcSpl_LevinsonDurbin().
 * The description header can be found in signal_processing_library.h
 *
 */

#include "signal_processing_library.h"

#define SPL_LEVINSON_MAXORDER 20

WebRtc_Word16 WebRtcSpl_LevinsonDurbin(WebRtc_Word32 *R, WebRtc_Word16 *A, WebRtc_Word16 *K,
                                       WebRtc_Word16 order)
{
    WebRtc_Word16 i, j;
    // Auto-correlation coefficients in high precision
    WebRtc_Word16 R_hi[SPL_LEVINSON_MAXORDER + 1], R_low[SPL_LEVINSON_MAXORDER + 1];
    // LPC coefficients in high precision
    WebRtc_Word16 A_hi[SPL_LEVINSON_MAXORDER + 1], A_low[SPL_LEVINSON_MAXORDER + 1];
    // LPC coefficients for next iteration
    WebRtc_Word16 A_upd_hi[SPL_LEVINSON_MAXORDER + 1], A_upd_low[SPL_LEVINSON_MAXORDER + 1];
    // Reflection coefficient in high precision
    WebRtc_Word16 K_hi, K_low;
    // Prediction gain Alpha in high precision and with scale factor
    WebRtc_Word16 Alpha_hi, Alpha_low, Alpha_exp;
    WebRtc_Word16 tmp_hi, tmp_low;
    WebRtc_Word32 temp1W32, temp2W32, temp3W32;
    WebRtc_Word16 norm;

    // Normalize the autocorrelation R[0]...R[order+1]

    norm = WebRtcSpl_NormW32(R[0]);

    for (i = order; i >= 0; i--)
    {
        temp1W32 = WEBRTC_SPL_LSHIFT_W32(R[i], norm);
        // Put R in hi and low format
        R_hi[i] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
        R_low[i] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
                - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)R_hi[i], 16)), 1);
    }

    // K = A[1] = -R[1] / R[0]

    temp2W32 = WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)R_hi[1],16)
            + WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)R_low[1],1); // R[1] in Q31
    temp3W32 = WEBRTC_SPL_ABS_W32(temp2W32); // abs R[1]
    temp1W32 = WebRtcSpl_DivW32HiLow(temp3W32, R_hi[0], R_low[0]); // abs(R[1])/R[0] in Q31
    // Put back the sign on R[1]
    if (temp2W32 > 0)
    {
        temp1W32 = -temp1W32;
    }

    // Put K in hi and low format
    K_hi = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
    K_low = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
            - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)K_hi, 16)), 1);

    // Store first reflection coefficient
    K[0] = K_hi;

    temp1W32 = WEBRTC_SPL_RSHIFT_W32(temp1W32, 4); // A[1] in Q27

    // Put A[1] in hi and low format
    A_hi[1] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
    A_low[1] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
            - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_hi[1], 16)), 1);

    // Alpha = R[0] * (1-K^2)

    temp1W32 = (((WEBRTC_SPL_MUL_16_16(K_hi, K_low) >> 14) + WEBRTC_SPL_MUL_16_16(K_hi, K_hi))
            << 1); // temp1W32 = k^2 in Q31

    temp1W32 = WEBRTC_SPL_ABS_W32(temp1W32); // Guard against <0
    temp1W32 = (WebRtc_Word32)0x7fffffffL - temp1W32; // temp1W32 = (1 - K[0]*K[0]) in Q31

    // Store temp1W32 = 1 - K[0]*K[0] on hi and low format
    tmp_hi = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
    tmp_low = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
            - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)tmp_hi, 16)), 1);

    // Calculate Alpha in Q31
    temp1W32 = ((WEBRTC_SPL_MUL_16_16(R_hi[0], tmp_hi)
            + (WEBRTC_SPL_MUL_16_16(R_hi[0], tmp_low) >> 15)
            + (WEBRTC_SPL_MUL_16_16(R_low[0], tmp_hi) >> 15)) << 1);

    // Normalize Alpha and put it in hi and low format

    Alpha_exp = WebRtcSpl_NormW32(temp1W32);
    temp1W32 = WEBRTC_SPL_LSHIFT_W32(temp1W32, Alpha_exp);
    Alpha_hi = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
    Alpha_low = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
            - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)Alpha_hi, 16)), 1);

    // Perform the iterative calculations in the Levinson-Durbin algorithm

    for (i = 2; i <= order; i++)
    {
        /*                    ----
         temp1W32 =  R[i] + > R[j]*A[i-j]
         /
         ----
         j=1..i-1
         */

        temp1W32 = 0;

        for (j = 1; j < i; j++)
        {
            // temp1W32 is in Q31
            temp1W32 += ((WEBRTC_SPL_MUL_16_16(R_hi[j], A_hi[i-j]) << 1)
                    + (((WEBRTC_SPL_MUL_16_16(R_hi[j], A_low[i-j]) >> 15)
                            + (WEBRTC_SPL_MUL_16_16(R_low[j], A_hi[i-j]) >> 15)) << 1));
        }

        temp1W32 = WEBRTC_SPL_LSHIFT_W32(temp1W32, 4);
        temp1W32 += (WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)R_hi[i], 16)
                + WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)R_low[i], 1));

        // K = -temp1W32 / Alpha
        temp2W32 = WEBRTC_SPL_ABS_W32(temp1W32); // abs(temp1W32)
        temp3W32 = WebRtcSpl_DivW32HiLow(temp2W32, Alpha_hi, Alpha_low); // abs(temp1W32)/Alpha

        // Put the sign of temp1W32 back again
        if (temp1W32 > 0)
        {
            temp3W32 = -temp3W32;
        }

        // Use the Alpha shifts from earlier to de-normalize
        norm = WebRtcSpl_NormW32(temp3W32);
        if ((Alpha_exp <= norm) || (temp3W32 == 0))
        {
            temp3W32 = WEBRTC_SPL_LSHIFT_W32(temp3W32, Alpha_exp);
        } else
        {
            if (temp3W32 > 0)
            {
                temp3W32 = (WebRtc_Word32)0x7fffffffL;
            } else
            {
                temp3W32 = (WebRtc_Word32)0x80000000L;
            }
        }

        // Put K on hi and low format
        K_hi = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp3W32, 16);
        K_low = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp3W32 - WEBRTC_SPL_LSHIFT_W32(K_hi, 16)), 1);

        // Store Reflection coefficient in Q15
        K[i - 1] = K_hi;

        // Test for unstable filter.
        // If unstable return 0 and let the user decide what to do in that case

        if ((WebRtc_Word32)WEBRTC_SPL_ABS_W16(K_hi) > (WebRtc_Word32)32750)
        {
            return 0; // Unstable filter
        }

        /*
         Compute updated LPC coefficient: Anew[i]
         Anew[j]= A[j] + K*A[i-j]   for j=1..i-1
         Anew[i]= K
         */

        for (j = 1; j < i; j++)
        {
            // temp1W32 = A[j] in Q27
            temp1W32 = WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_hi[j],16)
                    + WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_low[j],1);

            // temp1W32 += K*A[i-j] in Q27
            temp1W32 += ((WEBRTC_SPL_MUL_16_16(K_hi, A_hi[i-j])
                    + (WEBRTC_SPL_MUL_16_16(K_hi, A_low[i-j]) >> 15)
                    + (WEBRTC_SPL_MUL_16_16(K_low, A_hi[i-j]) >> 15)) << 1);

            // Put Anew in hi and low format
            A_upd_hi[j] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
            A_upd_low[j] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
                    - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_upd_hi[j], 16)), 1);
        }

        // temp3W32 = K in Q27 (Convert from Q31 to Q27)
        temp3W32 = WEBRTC_SPL_RSHIFT_W32(temp3W32, 4);

        // Store Anew in hi and low format
        A_upd_hi[i] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp3W32, 16);
        A_upd_low[i] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp3W32
                - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_upd_hi[i], 16)), 1);

        // Alpha = Alpha * (1-K^2)

        temp1W32 = (((WEBRTC_SPL_MUL_16_16(K_hi, K_low) >> 14)
                + WEBRTC_SPL_MUL_16_16(K_hi, K_hi)) << 1); // K*K in Q31

        temp1W32 = WEBRTC_SPL_ABS_W32(temp1W32); // Guard against <0
        temp1W32 = (WebRtc_Word32)0x7fffffffL - temp1W32; // 1 - K*K  in Q31

        // Convert 1- K^2 in hi and low format
        tmp_hi = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
        tmp_low = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
                - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)tmp_hi, 16)), 1);

        // Calculate Alpha = Alpha * (1-K^2) in Q31
        temp1W32 = ((WEBRTC_SPL_MUL_16_16(Alpha_hi, tmp_hi)
                + (WEBRTC_SPL_MUL_16_16(Alpha_hi, tmp_low) >> 15)
                + (WEBRTC_SPL_MUL_16_16(Alpha_low, tmp_hi) >> 15)) << 1);

        // Normalize Alpha and store it on hi and low format

        norm = WebRtcSpl_NormW32(temp1W32);
        temp1W32 = WEBRTC_SPL_LSHIFT_W32(temp1W32, norm);

        Alpha_hi = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32(temp1W32, 16);
        Alpha_low = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32
                - WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)Alpha_hi, 16)), 1);

        // Update the total normalization of Alpha
        Alpha_exp = Alpha_exp + norm;

        // Update A[]

        for (j = 1; j <= i; j++)
        {
            A_hi[j] = A_upd_hi[j];
            A_low[j] = A_upd_low[j];
        }
    }

    /*
     Set A[0] to 1.0 and store the A[i] i=1...order in Q12
     (Convert from Q27 and use rounding)
     */

    A[0] = 4096;

    for (i = 1; i <= order; i++)
    {
        // temp1W32 in Q27
        temp1W32 = WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_hi[i], 16)
                + WEBRTC_SPL_LSHIFT_W32((WebRtc_Word32)A_low[i], 1);
        // Round and store upper word
        A[i] = (WebRtc_Word16)WEBRTC_SPL_RSHIFT_W32((temp1W32<<1)+(WebRtc_Word32)32768, 16);
    }
    return 1; // Stable filters
}
