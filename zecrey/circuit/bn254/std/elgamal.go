/*
 * Copyright © 2021 Zecrey Protocol
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package std

/*
	ElGamalEncConstraints describes ElGamal Enc in circuit
*/
type ElGamalEncConstraints struct {
	CL Point // Pk^r
	CR Point // g^r Waste^b
}

func (tool *EccTool) NegElgamal(C ElGamalEncConstraints) ElGamalEncConstraints {
	return ElGamalEncConstraints{
		CL: *C.CL.Neg(tool.api, &C.CL),
		CR: *C.CR.Neg(tool.api, &C.CR),
	}
}

func (tool *EccTool) Enc(h Point, b Variable, r Variable, pk Point) ElGamalEncConstraints {
	var CL, gr, CR Point
	CL.ScalarMulNonFixedBase(tool.api, &pk, r, tool.params)
	gr.ScalarMulFixedBase(tool.api, tool.params.BaseX, tool.params.BaseY, r, tool.params)
	CR.ScalarMulNonFixedBase(tool.api, &h, b, tool.params)
	CR.AddGeneric(tool.api, &CR, &gr, tool.params)
	return ElGamalEncConstraints{CL: CL, CR: CR}
}

func (tool *EccTool) EncAdd(C, CDelta ElGamalEncConstraints) ElGamalEncConstraints {
	C.CL.AddGeneric(tool.api, &C.CL, &CDelta.CL, tool.params)
	C.CR.AddGeneric(tool.api, &C.CR, &CDelta.CR, tool.params)
	return C
}

func ZeroElgamal(api API) ElGamalEncConstraints {
	return ElGamalEncConstraints{CL: zeroPoint(api), CR: zeroPoint(api)}
}

func SelectElgamal(api API, flag Variable, a, b ElGamalEncConstraints) ElGamalEncConstraints {
	CLX := api.Select(flag, a.CL.X, b.CL.X)
	CLY := api.Select(flag, a.CL.Y, b.CL.Y)
	CRX := api.Select(flag, a.CR.X, b.CR.X)
	CRY := api.Select(flag, a.CR.Y, b.CR.Y)
	return ElGamalEncConstraints{CL: Point{X: CLX, Y: CLY}, CR: Point{X: CRX, Y: CRY}}
}

func printPoint(api API, a Point) {
	api.Println(a.X)
	api.Println(a.Y)
}

func printEnc(api API, a ElGamalEncConstraints) {
	api.Println(a.CL.X)
	api.Println(a.CL.Y)
	api.Println(a.CR.X)
	api.Println(a.CR.Y)
}
